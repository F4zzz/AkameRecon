#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de análise de serviços web
Realiza a análise de serviços HTTP/HTTPS em alvos específicos,
coletando status, headers, títulos e tecnologias utilizadas.
"""

import os
import re
import json
import logging
import subprocess
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from tqdm import tqdm
import socket

from utils import helpers

# Configurar logger
logger = logging.getLogger("AkameRecon")

# Configurações padrão para análise web
DEFAULT_WEB_CONFIG = {
    'headers_to_collect': [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ],
    'follow_redirects': True,
    'max_redirects': 5,
    'screenshot': False,
    'timeout': 8,
    'threads': 5,
    'tech_detection': True,
    'max_workers': 5,
    'user_agent_rotation': False,
    'whatweb_options': [
        '--no-errors',
        '--aggression 1',
        '--follow-redirect=never',
        '--log-json=-'
    ],
    'batch_size': 50,  # Tamanho do lote para processamento em batch
    'use_batch_processing': True,  # Se deve usar processamento em batch
    'prioritize_common_web_ports': True  # Priorizar portas web comuns
}

def check_web_services(targets, config, dns_results=None, port_results=None):
    """
    Verifica serviços web em uma lista de alvos, aproveitando resultados DNS e scan de portas prévios
    
    Args:
        targets (list): Lista de alvos no formato (domínio, porta)
        config (dict): Configurações da ferramenta
        dns_results (dict): Resultados prévios de resolução DNS
        port_results (dict): Resultados prévios de escaneamento de portas
    
    Returns:
        dict: Resultados da análise de serviços web
    """
    if not targets:
        logger.warning("Nenhum alvo para verificar serviços web")
        return {}
    
    logger.info(f"Verificando serviços web em {len(targets)} alvos")
    
    # Obter configurações
    web_config = config.get('web_scan', {})
    threads = web_config.get('threads', DEFAULT_WEB_CONFIG['threads'])
    follow_redirects = web_config.get('follow_redirects', DEFAULT_WEB_CONFIG['follow_redirects'])
    timeout = web_config.get('timeout', DEFAULT_WEB_CONFIG['timeout'])
    user_agent = config.get('general', {}).get('user_agent', helpers.random_user_agent())
    use_batch = web_config.get('use_batch_processing', DEFAULT_WEB_CONFIG['use_batch_processing'])
    batch_size = web_config.get('batch_size', DEFAULT_WEB_CONFIG['batch_size'])
    prioritize_common = web_config.get('prioritize_common_web_ports', DEFAULT_WEB_CONFIG['prioritize_common_web_ports'])
    
    # Determinar a estratégia
    use_httpx = helpers.is_command_available("httpx") and web_config.get('use_httpx', True)
    use_whatweb = helpers.is_command_available("whatweb") and web_config.get('tech_detection', True)
    
    results = {}
    skipped = []
    errors = []
    
    # Preparar lista de URLs para verificar, filtrando com base em resultados prévios
    urls_to_check = []
    for domain, port in targets:
        # Se tivermos resultados DNS, verificar se o domínio resolve
        if dns_results and domain in dns_results:
            if not dns_results[domain]['is_resolvable']:
                logger.debug(f"Ignorando {domain}:{port} - domínio não resolve")
                skipped.append(f"http{'s' if port in [443, 8443] else ''}://{domain}:{port}")
                continue
            
            # Se tivermos resultados de porta, verificar se a porta está aberta
            if port_results:
                # Verificar se algum dos IPs do domínio tem a porta aberta
                ips = dns_results[domain].get('ips', [])
                port_open = False
                
                for ip in ips:
                    if ip in port_results and port in [int(p) for p in port_results[ip].get('open_ports', [])]:
                        port_open = True
                        break
                
                if not port_open:
                    logger.debug(f"Ignorando {domain}:{port} - porta fechada")
                    skipped.append(f"http{'s' if port in [443, 8443] else ''}://{domain}:{port}")
                    continue
        
        protocol = "https" if port == 443 or port == 8443 else "http"
        url = f"{protocol}://{domain}:{port}"
        urls_to_check.append((url, domain, port))
    
    if not urls_to_check:
        logger.info("Nenhum alvo válido para verificação web após filtro")
        return {}
    
    # Priorizar portas comuns se configurado
    if prioritize_common:
        # Colocar portas 80 e 443 primeiro, seguidas de outras portas
        priority_order = {80: 0, 443: 1, 8080: 2, 8443: 3}
        urls_to_check.sort(key=lambda x: priority_order.get(x[2], 999))
        logger.debug("Alvos priorizados: portas comuns (80, 443) serão verificadas primeiro")
    
    logger.info(f"Verificando {len(urls_to_check)} alvos web após filtro")
    
    # Se usar processamento em batch para httpx & whatweb
    if use_batch and use_httpx:
        batch_results = process_urls_in_batch(
            [url for url, _, _ in urls_to_check], 
            web_config, 
            batch_size,
            use_whatweb
        )
        
        # Processar resultados do batch
        for url, domain, port in urls_to_check:
            target_key = f"{domain}:{port}"
            if url in batch_results:
                results[target_key] = batch_results[url]
            else:
                errors.append((url, "Falha no processamento em batch"))
    else:
        # Processamento tradicional - um a um
        results = process_urls_individually(urls_to_check, web_config, use_httpx, use_whatweb, errors, skipped)
    
    # Log de estatísticas
    total = len(urls_to_check)
    success = len(results)
    skipped_count = len(skipped)
    error_count = len(errors)
    
    logger.info(f"\nAnálise de serviços web concluída:")
    logger.info(f"✓ Sucesso: {success}/{total}")
    if skipped_count:
        logger.info(f"- Ignorados: {skipped_count}")
    if error_count:
        logger.info(f"✗ Erros: {error_count}")
        for url, error in errors[:5]:  # Mostra apenas os 5 primeiros erros
            logger.debug(f"  - {url}: {error}")
        if error_count > 5:
            logger.debug(f"  ... e mais {error_count - 5} erros")
    
    return results

def process_urls_in_batch(urls, config, batch_size=50, use_whatweb=True):
    """
    Processa URLs em lotes usando httpx e whatweb
    
    Args:
        urls (list): Lista de URLs para verificar
        config (dict): Configurações
        batch_size (int): Tamanho do lote
        use_whatweb (bool): Se deve detectar tecnologias com whatweb
    
    Returns:
        dict: Resultados indexados por URL
    """
    results = {}
    
    # Dividir em lotes para evitar comandos muito longos
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        logger.debug(f"Processando lote {i//batch_size+1}/{(len(urls)-1)//batch_size+1} ({len(batch)} URLs)")
        
        # Executar httpx em lote
        httpx_results = check_with_httpx_batch(batch, config)
        
        # Se configurado, executar whatweb em lote para os URLs que responderam
        if use_whatweb and httpx_results:
            whatweb_urls = [url for url, data in httpx_results.items() 
                          if data.get('status_code') and 100 <= data.get('status_code') < 600]
            
            if whatweb_urls:
                whatweb_results = detect_with_whatweb_batch(whatweb_urls, config)
                
                # Mesclar resultados
                for url, httpx_data in httpx_results.items():
                    if url in whatweb_results:
                        tech_info = whatweb_results[url]
                        httpx_data['technologies'] = tech_info.get('technologies', [])
                        httpx_data['cms'] = tech_info.get('cms')
                        httpx_data['frameworks'] = tech_info.get('frameworks', [])
                        httpx_data['javascript'] = tech_info.get('javascript', [])
                        httpx_data['analytics'] = tech_info.get('analytics', [])
                        httpx_data['server'] = tech_info.get('server') or httpx_data.get('server')
                    else:
                        # Fallback para URLs que whatweb não conseguiu processar
                        httpx_data['technologies'] = detect_technologies(url, httpx_data.get('html', ''))
                    
                    results[url] = httpx_data
            else:
                # Se não tiver URLs para whatweb, usar apenas resultados do httpx
                for url, data in httpx_results.items():
                    data['technologies'] = detect_technologies(url, data.get('html', ''))
                    results[url] = data
                
        else:
            # Se não usar whatweb, adicionar detecção básica
            for url, data in httpx_results.items():
                data['technologies'] = detect_technologies(url, data.get('html', ''))
                results[url] = data
    
    return results

def process_urls_individually(urls_to_check, web_config, use_httpx, use_whatweb, errors, skipped):
    """
    Processa URLs individualmente usando threads
    
    Args:
        urls_to_check (list): Lista de tuplas (url, domain, port)
        web_config (dict): Configurações
        use_httpx (bool): Se deve usar httpx
        use_whatweb (bool): Se deve usar whatweb
        errors (list): Lista para armazenar erros
        skipped (list): Lista para armazenar URLs ignorados
    
    Returns:
        dict: Resultados indexados por chave de alvo
    """
    results = {}
    threads = web_config.get('threads', DEFAULT_WEB_CONFIG['threads'])
    user_agent = web_config.get('user_agent', helpers.random_user_agent())
    
    # Função para verificar um único URL
    def check_url(url_data):
        url, domain, port = url_data
        target_key = f"{domain}:{port}"
        
        try:
            if use_httpx:
                result = check_with_httpx(url, web_config, skip_connectivity_check=True)
                if result.get('error'):
                    logger.debug(f"Erro em {url}: {result['error']}")
                    errors.append((url, result['error']))
                    return target_key, None
            else:
                result = check_with_requests(url, web_config, user_agent)
            
            if result and not result.get('error'):
                if use_whatweb:
                    tech_info = detect_with_whatweb(url, web_config)
                    if tech_info:
                        result['technologies'] = tech_info.get('technologies', [])
                        result['cms'] = tech_info.get('cms')
                        result['frameworks'] = tech_info.get('frameworks', [])
                        result['javascript'] = tech_info.get('javascript', [])
                        result['analytics'] = tech_info.get('analytics', [])
                        result['server'] = tech_info.get('server') or result.get('server')
                else:
                    result['technologies'] = detect_technologies(url, result.get('html', ''))
                
                return target_key, result
            else:
                skipped.append(url)
                return target_key, None
        
        except Exception as e:
            logger.debug(f"Erro ao verificar {url}: {e}")
            errors.append((url, str(e)))
            return target_key, None
    
    # Verificar URLs em paralelo
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(check_url, url_data): url_data for url_data in urls_to_check}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_url), 
                         total=len(urls_to_check), desc="Verificando serviços web", ncols=80):
            try:
                target_key, result = future.result()
                if result:
                    results[target_key] = result
            except Exception as e:
                logger.error(f"Erro ao processar resultado web: {e}")
    
    return results

def check_with_httpx(url, config, skip_connectivity_check=False):
    """
    Verifica um URL usando httpx via subprocess
    
    Args:
        url (str): URL para verificar
        config (dict): Configurações de web scan
        skip_connectivity_check (bool): Se True, pula verificação de conectividade
    
    Returns:
        dict: Informações do serviço web
    """
    result = {
        'url': url,
        'status_code': None,
        'title': None,
        'headers': {},
        'html': None,
        'server': None,
        'content_type': None,
        'redirect_url': None,
        'error': None
    }
    
    try:
        # Verificar conectividade apenas se não devemos pular
        if not skip_connectivity_check:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Timeout curto para teste de conexão
            
            if not sock.connect_ex((host, port)) == 0:
                result['error'] = f"Host inacessível na porta {port}"
                return result
            
            sock.close()
        
        # Configurar httpx
        timeout = config.get('timeout', 8)
        
        cmd = [
            "httpx",
            "-u", url,
            "-silent",
            "-json",
            "-timeout", str(timeout),
            "-retries", "1",
            "-max-redirects", "2"
        ]
        
        if config.get('follow_redirects', True):
            cmd.append("-follow-redirects")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout + 2)
            
            if process.returncode == 0 and stdout.strip():
                try:
                    httpx_data = json.loads(stdout.strip())
                    
                    result['url'] = httpx_data.get('url', url)
                    result['status_code'] = httpx_data.get('status_code')
                    result['title'] = httpx_data.get('title')
                    result['headers'] = httpx_data.get('headers', {})
                    result['server'] = result['headers'].get('server')
                    result['content_type'] = result['headers'].get('content-type')
                    result['html'] = httpx_data.get('body')
                    
                except json.JSONDecodeError:
                    result['error'] = "Erro ao decodificar resposta JSON do httpx"
            else:
                result['error'] = stderr if stderr else "Sem resposta do httpx"
                
        except subprocess.TimeoutExpired:
            process.kill()
            result['error'] = f"Timeout após {timeout + 2}s"
            
    except socket.timeout:
        result['error'] = "Timeout na verificação de conectividade"
    except socket.gaierror:
        result['error'] = "Erro na resolução do hostname"
    except Exception as e:
        result['error'] = f"Erro ao verificar URL: {str(e)}"
    
    return result

def check_with_requests(url, config, user_agent):
    """
    Verifica um URL usando requests
    
    Args:
        url (str): URL para verificar
        config (dict): Configurações de web scan
        user_agent (str): User-Agent para usar
    
    Returns:
        dict: Informações do serviço web
    """
    result = {
        'url': url,
        'status_code': None,
        'title': None,
        'headers': {},
        'html': None,
        'server': None,
        'content_type': None,
        'redirect_url': None
    }
    
    try:
        # Configurar headers
        headers = {'User-Agent': user_agent}
        
        # Configurar timeout e redirecionamentos
        timeout = config.get('timeout', 5)
        allow_redirects = config.get('follow_redirects', True)
        max_redirects = config.get('max_redirects', 5)
        
        # Fazer requisição
        response = requests.get(
            url, 
            headers=headers, 
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False
        )
        
        # Preencher resultado
        result['status_code'] = response.status_code
        result['headers'] = dict(response.headers)
        result['server'] = response.headers.get('server')
        result['content_type'] = response.headers.get('content-type')
        
        # Verificar se houve redirecionamento
        if response.url != url:
            result['redirect_url'] = response.url
        
        # Extrair título se for HTML
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' in content_type:
            result['html'] = response.text
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                result['title'] = title_tag.text.strip()
        
        return result
    
    except requests.RequestException as e:
        logger.debug(f"Erro de requisição para {url}: {e}")
    except Exception as e:
        logger.error(f"Erro ao verificar {url} com requests: {e}")
    
    return None

def detect_technologies(url, html_content):
    """
    Detecta tecnologias utilizadas em um site
    Tenta usar Wappalyzer ou WhatWeb se disponíveis
    
    Args:
        url (str): URL do site
        html_content (str): Conteúdo HTML da página
    
    Returns:
        list: Lista de tecnologias detectadas
    """
    technologies = []
    
    # Tentar usar wappalyzergo se disponível
    if helpers.is_command_available("wappalyzergo"):
        try:
            cmd = ["wappalyzergo"]
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(input=html_content, timeout=10)
            
            if process.returncode == 0 and stdout.strip():
                try:
                    tech_data = json.loads(stdout.strip())
                    technologies = list(tech_data.keys())
                except json.JSONDecodeError:
                    pass
            
            if technologies:
                return technologies
        except Exception as e:
            logger.debug(f"Erro ao usar wappalyzergo: {e}")
    
    # Tentar usar whatweb se disponível
    if helpers.is_command_available("whatweb"):
        try:
            cmd = ["whatweb", "--no-errors", "--quiet", "--log-json", "-"]
            cmd.append(url)
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(timeout=15)
            
            if process.returncode == 0 and stdout.strip():
                try:
                    whatweb_data = json.loads(stdout.strip())
                    if isinstance(whatweb_data, list) and len(whatweb_data) > 0:
                        plugins = whatweb_data[0].get('plugins', {})
                        technologies = list(plugins.keys())
                except json.JSONDecodeError:
                    pass
            
            if technologies:
                return technologies
        except Exception as e:
            logger.debug(f"Erro ao usar whatweb: {e}")
    
    # Detecção básica se as ferramentas não estão disponíveis
    # Esta é uma versão simples, pode ser expandida
    if html_content:
        basic_techs = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Joomla': ['joomla', 'com_content'],
            'Drupal': ['drupal', 'drupal.js'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'React': ['react', 'reactjs'],
            'Angular': ['ng-', 'angular'],
            'Vue.js': ['vue'],
            'PHP': ['php'],
            'ASP.NET': ['asp.net', '__VIEWSTATE'],
            'Laravel': ['laravel'],
            'Django': ['django'],
            'Ruby on Rails': ['rails'],
            'IIS': ['iis'],
            'Nginx': ['nginx'],
            'Apache': ['apache'],
            'Cloudflare': ['cloudflare']
        }
        
        # Verificar cada tecnologia
        for tech, patterns in basic_techs.items():
            for pattern in patterns:
                if pattern.lower() in html_content.lower():
                    technologies.append(tech)
                    break
    
    return technologies

def detect_with_whatweb(url, config):
    """
    Detecta tecnologias web usando whatweb
    
    Args:
        url (str): URL para analisar
        config (dict): Configurações de web scan
    
    Returns:
        dict: Informações das tecnologias detectadas
    """
    tech_info = {
        'technologies': [],
        'cms': None,
        'frameworks': [],
        'javascript': [],
        'analytics': [],
        'server': None
    }
    
    try:
        # Configurar comando whatweb
        whatweb_options = config.get('whatweb_options', DEFAULT_WEB_CONFIG['whatweb_options'])
        cmd = ["whatweb"] + whatweb_options + [url]
        
        # Executar whatweb
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=15)
        
        if process.returncode == 0 and stdout.strip():
            try:
                whatweb_data = json.loads(stdout.strip())
                if isinstance(whatweb_data, list) and len(whatweb_data) > 0:
                    plugins = whatweb_data[0].get('plugins', {})
                    
                    # Processar resultados do whatweb
                    for plugin_name, plugin_data in plugins.items():
                        # Detectar servidor web
                        if plugin_name == 'HTTPServer':
                            tech_info['server'] = plugin_data.get('string', [None])[0]
                        
                        # Detectar CMS
                        elif plugin_name in ['WordPress', 'Drupal', 'Joomla']:
                            tech_info['cms'] = plugin_name
                            version = plugin_data.get('version', [None])[0]
                            if version:
                                tech_info['cms'] += f" {version}"
                        
                        # Detectar frameworks
                        elif plugin_name in ['Ruby-on-Rails', 'Django', 'Laravel', 'ASP.NET']:
                            tech_info['frameworks'].append(plugin_name)
                        
                        # Detectar bibliotecas JavaScript
                        elif plugin_name in ['jQuery', 'React', 'Angular', 'Vue.js']:
                            tech_info['javascript'].append(plugin_name)
                        
                        # Detectar analytics
                        elif plugin_name in ['Google-Analytics', 'Matomo']:
                            tech_info['analytics'].append(plugin_name)
                        
                        # Outras tecnologias
                        else:
                            tech_info['technologies'].append(plugin_name)
                    
                    # Remover duplicatas
                    tech_info['technologies'] = list(set(tech_info['technologies']))
                    tech_info['frameworks'] = list(set(tech_info['frameworks']))
                    tech_info['javascript'] = list(set(tech_info['javascript']))
                    tech_info['analytics'] = list(set(tech_info['analytics']))
            
            except json.JSONDecodeError:
                logger.error(f"Erro ao decodificar JSON do whatweb para {url}")
    
    except Exception as e:
        logger.error(f"Erro ao executar whatweb para {url}: {e}")
    
    return tech_info

def check_with_httpx_batch(urls, config):
    """
    Verifica múltiplos URLs em uma única execução do httpx
    
    Args:
        urls (list): Lista de URLs para verificar
        config (dict): Configurações
    
    Returns:
        dict: Resultados indexados por URL
    """
    results = {}
    timeout = config.get('timeout', 8)
    
    if not urls:
        return results
    
    # Preparar arquivo temporário com URLs
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
        for url in urls:
            temp.write(f"{url}\n")
        temp_path = temp.name
    
    try:
        # Configurar comando httpx para processar em batch
        cmd = [
            "httpx",
            "-l", temp_path,
            "-silent",
            "-json",
            "-timeout", str(timeout),
            "-retries", "1",
            "-max-redirects", "2",
            "-threads", str(min(50, len(urls)))  # Limitar threads a 50 ou número de URLs
        ]
        
        if config.get('follow_redirects', True):
            cmd.append("-follow-redirects")
        
        # Executar comando
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout * 2)
        
        # Processar resultados linha por linha (cada linha é um JSON)
        if process.returncode == 0 and stdout.strip():
            for line in stdout.strip().split('\n'):
                if not line:
                    continue
                    
                try:
                    httpx_data = json.loads(line)
                    url = httpx_data.get('url')
                    
                    if url:
                        results[url] = {
                            'url': url,
                            'status_code': httpx_data.get('status_code'),
                            'title': httpx_data.get('title'),
                            'headers': httpx_data.get('headers', {}),
                            'server': httpx_data.get('headers', {}).get('server'),
                            'content_type': httpx_data.get('headers', {}).get('content-type'),
                            'html': httpx_data.get('body'),
                            'technologies': []  # Será preenchido depois
                        }
                except json.JSONDecodeError:
                    logger.debug(f"Erro ao decodificar linha JSON: {line[:50]}...")
                except Exception as e:
                    logger.debug(f"Erro ao processar resultado do httpx: {e}")
        else:
            logger.warning(f"Erro ao executar httpx em batch: {stderr}")
            
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout ao executar httpx em batch após {timeout * 2}s")
    except Exception as e:
        logger.error(f"Erro ao executar httpx em batch: {e}")
    finally:
        # Limpar arquivo temporário
        try:
            os.remove(temp_path)
        except:
            pass
    
    return results

def detect_with_whatweb_batch(urls, config):
    """
    Detecta tecnologias web em múltiplos URLs em batch
    
    Args:
        urls (list): Lista de URLs para verificar
        config (dict): Configurações
    
    Returns:
        dict: Resultados indexados por URL
    """
    results = {}
    
    if not urls:
        return results
    
    # Preparar arquivo temporário com URLs
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
        for url in urls:
            temp.write(f"{url}\n")
        temp_path = temp.name
    
    try:
        # Configurar comando whatweb
        whatweb_options = config.get('whatweb_options', DEFAULT_WEB_CONFIG['whatweb_options'])
        cmd = ["whatweb", "--input-file", temp_path, "--log-json=-"]
        
        # Adicionar outras opções do whatweb
        for option in whatweb_options:
            if '--input-file' not in option and '--log-json' not in option:
                cmd.append(option)
        
        # Executar comando
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=30)  # Timeout de 30s para whatweb em batch
        
        if process.returncode == 0 and stdout.strip():
            try:
                whatweb_data = json.loads(stdout.strip())
                
                if isinstance(whatweb_data, list):
                    for entry in whatweb_data:
                        url = entry.get('target')
                        plugins = entry.get('plugins', {})
                        
                        if url:
                            tech_info = {
                                'technologies': [],
                                'cms': None,
                                'frameworks': [],
                                'javascript': [],
                                'analytics': [],
                                'server': None
                            }
                            
                            # Processar plugins do whatweb
                            for plugin_name, plugin_data in plugins.items():
                                # Detectar servidor web
                                if plugin_name == 'HTTPServer':
                                    tech_info['server'] = plugin_data.get('string', [None])[0]
                                
                                # Detectar CMS
                                elif plugin_name in ['WordPress', 'Drupal', 'Joomla']:
                                    tech_info['cms'] = plugin_name
                                    version = plugin_data.get('version', [None])[0]
                                    if version:
                                        tech_info['cms'] += f" {version}"
                                
                                # Detectar frameworks
                                elif plugin_name in ['Ruby-on-Rails', 'Django', 'Laravel', 'ASP.NET']:
                                    tech_info['frameworks'].append(plugin_name)
                                
                                # Detectar bibliotecas JavaScript
                                elif plugin_name in ['jQuery', 'React', 'Angular', 'Vue.js']:
                                    tech_info['javascript'].append(plugin_name)
                                
                                # Detectar analytics
                                elif plugin_name in ['Google-Analytics', 'Matomo']:
                                    tech_info['analytics'].append(plugin_name)
                                
                                # Outras tecnologias
                                else:
                                    tech_info['technologies'].append(plugin_name)
                            
                            # Remover duplicatas
                            tech_info['technologies'] = list(set(tech_info['technologies']))
                            tech_info['frameworks'] = list(set(tech_info['frameworks']))
                            tech_info['javascript'] = list(set(tech_info['javascript']))
                            tech_info['analytics'] = list(set(tech_info['analytics']))
                            
                            results[url] = tech_info
            except json.JSONDecodeError:
                logger.error(f"Erro ao decodificar JSON do whatweb em batch")
            except Exception as e:
                logger.error(f"Erro ao processar resultados do whatweb em batch: {e}")
    except Exception as e:
        logger.error(f"Erro ao executar whatweb em batch: {e}")
    finally:
        # Limpar arquivo temporário
        try:
            os.remove(temp_path)
        except:
            pass
    
    return results 