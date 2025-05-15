#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de enumeração de subdomínios
Utiliza técnicas passivas (OSINT) e ativas (bruteforce) para descobrir subdomínios.
Integra ferramentas como subfinder, amass e crt.sh.
"""

import os
import re
import json
import time
import logging
import requests
import subprocess
import concurrent.futures
import dns.resolver
import tldextract
from tqdm import tqdm

from utils import helpers

# Configurar logger
logger = logging.getLogger("AkameRecon")

# Configurações padrão para enumeração de subdomínios
DEFAULT_SUBDOMAIN_CONFIG = {
    # Fontes passivas
    'use_crt_sh': True,
    'use_subfinder': True,
    'use_amass': True,
    
    # Fontes ativas (mais intrusivas)
    'use_bruteforce': True,
    'use_amass_active': False,
    'use_alterations': True,
    
    # Caminhos e recursos
    'wordlist_path': 'utils/wordlists/mini.txt',  # Usar mini.txt em vez de common.txt por padrão
    
    # Configurações de timeouts
    'crt_sh_timeout': 30,
    'subfinder_timeout': 300,
    'amass_timeout': 600,
    'amass_active_timeout': 1200,
    
    # Configurações de bruteforce
    'max_bruteforce_workers': 5,  # Valor conservador por padrão
    'bruteforce_retry': 2,
    'bruteforce_timeout': 2,
    
    # Configurações de alterações
    'max_alterations': 100,  # Limitar número de alterações para evitar explosão combinatória
    'alteration_prefixes': ['dev', 'stage', 'test', 'prod', 'api'],
    'alteration_suffixes': ['-dev', '-stage', '-test', '-prod', '-api']
}

def enumerate_subdomains(domain, config):
    """
    Enumera subdomínios de um domínio usando múltiplas técnicas
    
    Args:
        domain (str): O domínio alvo
        config (dict): Configurações da ferramenta
    
    Returns:
        list: Lista de subdomínios únicos descobertos
    """
    logger.info(f"Iniciando enumeração de subdomínios para: {domain}")
    
    # Obter configurações com fallback para valores padrão
    subdomain_config = config.get('subdomain_enum', {})
    results = set()
    
    # Técnicas passivas (OSINT)
    if subdomain_config.get('use_crt_sh', DEFAULT_SUBDOMAIN_CONFIG['use_crt_sh']):
        logger.info("Coletando subdomínios de crt.sh...")
        crt_timeout = subdomain_config.get('crt_sh_timeout', DEFAULT_SUBDOMAIN_CONFIG['crt_sh_timeout'])
        results.update(enum_crtsh(domain, timeout=crt_timeout))
    
    if helpers.is_command_available("subfinder") and subdomain_config.get('use_subfinder', DEFAULT_SUBDOMAIN_CONFIG['use_subfinder']):
        logger.info("Executando subfinder...")
        subfinder_timeout = subdomain_config.get('subfinder_timeout', DEFAULT_SUBDOMAIN_CONFIG['subfinder_timeout'])
        results.update(enum_subfinder(domain, timeout=subfinder_timeout))
    
    if helpers.is_command_available("amass") and subdomain_config.get('use_amass', DEFAULT_SUBDOMAIN_CONFIG['use_amass']):
        logger.info("Executando amass (modo passivo)...")
        amass_timeout = subdomain_config.get('amass_timeout', DEFAULT_SUBDOMAIN_CONFIG['amass_timeout'])
        results.update(enum_amass(domain, passive=True, timeout=amass_timeout))
    
    # Técnicas ativas
    if subdomain_config.get('use_bruteforce', DEFAULT_SUBDOMAIN_CONFIG['use_bruteforce']):
        logger.info("Iniciando bruteforce de subdomínios...")
        # Obter caminho da wordlist com fallback
        wordlist_path_config = subdomain_config.get('wordlist_path', DEFAULT_SUBDOMAIN_CONFIG['wordlist_path'])
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), wordlist_path_config)
        
        if os.path.exists(wordlist_path):
            results.update(enum_bruteforce(domain, wordlist_path, config, subdomain_config))
        else:
            logger.warning(f"Wordlist não encontrada: {wordlist_path}")
    
    if helpers.is_command_available("amass") and subdomain_config.get('use_amass_active', DEFAULT_SUBDOMAIN_CONFIG['use_amass_active']):
        logger.info("Executando amass (modo ativo - pode demorar)...")
        amass_active_timeout = subdomain_config.get('amass_active_timeout', DEFAULT_SUBDOMAIN_CONFIG['amass_active_timeout'])
        results.update(enum_amass(domain, passive=False, timeout=amass_active_timeout))
    
    # Alterações de subdomínios conhecidos (permutações)
    if subdomain_config.get('use_alterations', DEFAULT_SUBDOMAIN_CONFIG['use_alterations']) and results:
        logger.info("Gerando alterações de subdomínios conhecidos...")
        max_alterations = subdomain_config.get('max_alterations', DEFAULT_SUBDOMAIN_CONFIG['max_alterations'])
        prefixes = subdomain_config.get('alteration_prefixes', DEFAULT_SUBDOMAIN_CONFIG['alteration_prefixes'])
        suffixes = subdomain_config.get('alteration_suffixes', DEFAULT_SUBDOMAIN_CONFIG['alteration_suffixes'])
        results.update(enum_alterations(results, domain, max_alterations, prefixes, suffixes))
    
    # Remover resultados inválidos e ordenar
    valid_results = []
    for subdomain in results:
        if helpers.is_valid_domain(subdomain) and subdomain.endswith(domain):
            valid_results.append(subdomain)
    
    valid_results = sorted(list(set(valid_results)))
    logger.info(f"Total de subdomínios encontrados: {len(valid_results)}")
    
    return valid_results

def enum_crtsh(domain, timeout=30):
    """
    Enumera subdomínios usando crt.sh
    
    Args:
        domain (str): O domínio alvo
        timeout (int): Timeout em segundos para a requisição
    
    Returns:
        set: Conjunto de subdomínios descobertos
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            try:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    # Separar múltiplos domínios se existirem
                    if '\n' in name:
                        names = name.split('\n')
                        for n in names:
                            if n.endswith(f'.{domain}') or n == domain:
                                subdomains.add(n)
                    else:
                        if name.endswith(f'.{domain}') or name == domain:
                            subdomains.add(name)
            except json.JSONDecodeError:
                logger.error("Erro ao decodificar JSON de crt.sh")
    except requests.RequestException as e:
        logger.error(f"Erro ao consultar crt.sh: {e}")
    
    return subdomains

def enum_subfinder(domain, timeout=300):
    """
    Enumera subdomínios usando subfinder
    
    Args:
        domain (str): O domínio alvo
        timeout (int): Timeout em segundos para o processo
    
    Returns:
        set: Conjunto de subdomínios descobertos
    """
    subdomains = set()
    
    try:
        process = subprocess.Popen(
            ["subfinder", "-d", domain, "-silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Definir timeout para o processo
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode == 0:
                for line in stdout.strip().split('\n'):
                    if line:
                        subdomains.add(line.strip().lower())
            else:
                logger.error(f"Erro ao executar subfinder: {stderr}")
        except subprocess.TimeoutExpired:
            process.kill()
            logger.warning(f"Subfinder atingiu o timeout de {timeout}s")
    except Exception as e:
        logger.error(f"Erro ao executar subfinder: {e}")
    
    return subdomains

def enum_amass(domain, passive=True, timeout=600):
    """
    Enumera subdomínios usando amass
    
    Args:
        domain (str): O domínio alvo
        passive (bool): Se deve usar apenas técnicas passivas
        timeout (int): Timeout em segundos para o processo
    
    Returns:
        set: Conjunto de subdomínios descobertos
    """
    subdomains = set()
    
    try:
        cmd = ["amass", "enum"]
        
        if passive:
            cmd.extend(["-passive"])
        
        cmd.extend(["-d", domain])
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode == 0:
                for line in stdout.strip().split('\n'):
                    if line:
                        subdomains.add(line.strip().lower())
            else:
                logger.error(f"Erro ao executar amass: {stderr}")
        except subprocess.TimeoutExpired:
            process.kill()
            logger.warning(f"Amass atingiu o timeout de {timeout}s")
    except Exception as e:
        logger.error(f"Erro ao executar amass: {e}")
    
    return subdomains

def enum_bruteforce(domain, wordlist_path, config, subdomain_config):
    """
    Realiza bruteforce de subdomínios usando dnspython
    
    Args:
        domain (str): O domínio alvo
        wordlist_path (str): Caminho para a wordlist
        config (dict): Configurações gerais da ferramenta
        subdomain_config (dict): Configurações específicas para enumeração de subdomínios
    
    Returns:
        set: Conjunto de subdomínios descobertos
    """
    subdomains = set()
    
    # Carregar wordlist
    try:
        wordlist = helpers.load_wordlist(wordlist_path)
        logger.info(f"Wordlist carregada com {len(wordlist)} entradas")
    except Exception as e:
        logger.error(f"Erro ao carregar wordlist: {e}")
        return subdomains
    
    # Obter configurações com fallback para valores padrão
    dns_config = config.get('dns', {})
    resolvers = dns_config.get('resolvers', ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'])
    max_workers = subdomain_config.get('max_bruteforce_workers', DEFAULT_SUBDOMAIN_CONFIG['max_bruteforce_workers'])
    retry_count = subdomain_config.get('bruteforce_retry', DEFAULT_SUBDOMAIN_CONFIG['bruteforce_retry'])
    timeout = subdomain_config.get('bruteforce_timeout', DEFAULT_SUBDOMAIN_CONFIG['bruteforce_timeout'])
    
    # Registrar configurações para depuração
    logger.debug(f"Bruteforce com {max_workers} workers, timeout={timeout}s, retry={retry_count}")
    
    # Função para verificar um único subdomínio
    def check_subdomain(prefix):
        subdomain = f"{prefix}.{domain}"
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolvers[hash(subdomain) % len(resolvers)]]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        for attempt in range(retry_count + 1):
            try:
                resolver.resolve(subdomain, 'A')
                return subdomain
            except dns.resolver.NXDOMAIN:
                break  # Domínio não existe, não precisa tentar novamente
            except Exception as e:
                if attempt == retry_count:
                    break
                time.sleep(0.1)  # Pequena pausa entre tentativas
        
        return None
    
    # Executar bruteforce em paralelo - limitando número de workers para evitar sobrecarga
    safe_max_workers = min(max_workers, 10)  # Nunca exceder 10 workers, mesmo se config for maior
    with concurrent.futures.ThreadPoolExecutor(max_workers=safe_max_workers) as executor:
        future_to_prefix = {executor.submit(check_subdomain, prefix): prefix for prefix in wordlist}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_prefix), 
                         total=len(wordlist), desc="Bruteforce", ncols=80):
            try:
                result = future.result()
                if result:
                    subdomains.add(result)
            except Exception as e:
                prefix = future_to_prefix[future]
                logger.debug(f"Erro ao verificar {prefix}.{domain}: {e}")
    
    return subdomains

def enum_alterations(known_subdomains, domain, max_alterations=100, prefixes=None, suffixes=None):
    """
    Gera alterações de subdomínios conhecidos
    
    Args:
        known_subdomains (set): Conjunto de subdomínios já conhecidos
        domain (str): O domínio alvo
        max_alterations (int): Número máximo de alterações a gerar
        prefixes (list): Lista de prefixos para adicionar
        suffixes (list): Lista de sufixos para adicionar
    
    Returns:
        set: Conjunto de alterações de subdomínios
    """
    if prefixes is None:
        prefixes = DEFAULT_SUBDOMAIN_CONFIG['alteration_prefixes']
    
    if suffixes is None:
        suffixes = DEFAULT_SUBDOMAIN_CONFIG['alteration_suffixes']
    
    alterations = set()
    known_list = list(known_subdomains)
    
    # Limitar para evitar explosão combinatória
    if len(known_list) > 20:
        known_list = known_list[:20]
    
    for subdomain in known_list:
        # Extrair o prefixo do subdomínio
        ext = tldextract.extract(subdomain)
        if not ext.subdomain:
            continue
        
        parts = ext.subdomain.split('.')
        
        # Gerar alterações com prefixos
        for prefix in prefixes:
            for part in parts:
                new_subdomain = f"{prefix}-{part}.{ext.domain}.{ext.suffix}"
                if new_subdomain not in known_subdomains:
                    alterations.add(new_subdomain)
                
                # Verificar limite de alterações
                if len(alterations) >= max_alterations:
                    return alterations
        
        # Gerar alterações com sufixos
        for suffix in suffixes:
            for part in parts:
                new_subdomain = f"{part}{suffix}.{ext.domain}.{ext.suffix}"
                if new_subdomain not in known_subdomains:
                    alterations.add(new_subdomain)
                
                # Verificar limite de alterações
                if len(alterations) >= max_alterations:
                    return alterations
    
    return alterations 