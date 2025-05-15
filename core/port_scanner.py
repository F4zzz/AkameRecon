#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de escaneamento de portas
Utiliza nmap (via python-nmap) e naabu para descobrir portas abertas 
e serviços em execução nos alvos especificados.
"""

import os
import re
import json
import logging
import concurrent.futures
import subprocess
import socket
import nmap
from tqdm import tqdm

from utils import helpers

# Configurar logger
logger = logging.getLogger("AkameRecon")

# Configurações padrão para escaneamento de portas
DEFAULT_PORT_CONFIG = {
    # Lista de portas padrão para escanear (comuns HTTP, SSH, etc)
    'default_ports': [21, 22, 23, 25, 53, 80, 443, 8080, 8443],
    # Se deve fazer um escaneamento completo (1-65535)
    'full_scan': False,
    # Tipo de scan nmap (-sT, -sS, etc)
    'scan_type': 'sT',
    # Número máximo de threads
    'threads': 5,
    # Se deve usar naabu (se disponível)
    'use_naabu': False,
    # Timeout em segundos para escaneamento
    'timeout': 5,
    # Taxa mínima de pacotes por segundo
    'min_rate': 100,
    # Flags nmap para detecção de serviço
    'service_detection': True,
    # Flags nmap para detecção de sistema operacional (requer root)
    'os_detection': False,
    # Scripts NSE a serem executados
    'nse_scripts': ['banner,http-title,ssl-cert,ssh-auth-methods'],
    # Intensidade da detecção de serviço (0-9)
    'service_intensity': 5,
    # Flags nmap adicionais como string
    'additional_args': '',
    # Portas naabu taxa máxima
    'naabu_rate': 100,
    # Timeout para socket scan
    'socket_timeout': 1
}

def scan_ports(targets, config):
    """
    Escaneia portas em um ou mais alvos
    
    Args:
        targets (list): Lista de IPs ou domínios para escanear
        config (dict): Configurações da ferramenta
    
    Returns:
        dict: Dicionário com resultados do escaneamento para cada alvo
    """
    if not targets:
        logger.warning("Nenhum alvo para escanear portas")
        return {}
    
    logger.info(f"Iniciando escaneamento de portas em {len(targets)} alvos")
    
    # Obter configurações com fallback para valores padrão
    port_config = config.get('port_scan', {})
    default_ports = port_config.get('default_ports', DEFAULT_PORT_CONFIG['default_ports'])
    full_scan = port_config.get('full_scan', DEFAULT_PORT_CONFIG['full_scan'])
    scan_type = port_config.get('scan_type', DEFAULT_PORT_CONFIG['scan_type'])
    threads = min(port_config.get('threads', DEFAULT_PORT_CONFIG['threads']), 10)  # Limitar a 10 threads máximo
    
    # Registrar configurações usadas para depuração
    logger.debug(f"Configuração de scan: threads={threads}, scan_type={scan_type}, full_scan={full_scan}")
    
    # Determinar a estratégia de escaneamento
    use_nmap = True
    use_naabu = helpers.is_command_available('naabu') and port_config.get('use_naabu', DEFAULT_PORT_CONFIG['use_naabu'])
    
    results = {}
    
    # Função para processar um único alvo
    def scan_target(target):
        target_result = {
            'target': target,
            'open_ports': [],
            'services': {}
        }
        
        # Validar alvo antes de escanear
        if not helpers.is_valid_ip(target) and not helpers.is_valid_domain(target):
            logger.warning(f"Alvo inválido: {target}")
            return target, None
        
        try:
            # Usar naabu para uma varredura rápida inicial (se disponível)
            if use_naabu:
                logger.debug(f"Usando naabu para escanear {target}")
                naabu_ports = scan_with_naabu(target, port_config)
                if naabu_ports:
                    target_result['open_ports'] = naabu_ports
            
            # Usar nmap para escaneamento detalhado
            if use_nmap:
                logger.debug(f"Usando nmap para escanear {target}")
                nmap_results = scan_with_nmap(target, port_config, 
                                            target_result['open_ports'] if target_result['open_ports'] else None)
                
                if nmap_results:
                    # Atualizar resultados com dados do nmap
                    if not target_result['open_ports'] and 'open_ports' in nmap_results:
                        target_result['open_ports'] = nmap_results['open_ports']
                    
                    if 'services' in nmap_results:
                        target_result['services'] = nmap_results['services']
            
            # Se nem nmap nem naabu estiverem disponíveis, usar socket puro
            if not use_nmap and not use_naabu:
                logger.debug(f"Usando socket para escanear {target}")
                socket_ports = scan_with_socket(target, default_ports, port_config)
                if socket_ports:
                    target_result['open_ports'] = socket_ports
            
            return target, target_result if target_result['open_ports'] else None
        
        except Exception as e:
            logger.error(f"Erro ao escanear {target}: {e}")
            return target, None
    
    # Escanear em paralelo
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {executor.submit(scan_target, target): target for target in targets}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_target), 
                         total=len(targets), desc="Escaneando portas", ncols=80):
            try:
                target, result = future.result()
                if result:
                    results[target] = result
            except Exception as e:
                logger.error(f"Erro ao processar resultado do scan: {e}")
    
    # Contagem total de portas encontradas
    total_ports = sum(len(result['open_ports']) for result in results.values())
    logger.info(f"Escaneamento concluído. Encontradas {total_ports} portas abertas em {len(results)} alvos")
    
    return results

def scan_with_nmap(target, config, ports=None):
    """
    Escaneia um alvo usando python-nmap
    
    Args:
        target (str): IP ou domínio para escanear
        config (dict): Configurações de escaneamento de portas
        ports (list): Lista de portas para escanear (opcional)
    
    Returns:
        dict: Resultado do escaneamento nmap
    """
    result = {
        'open_ports': [],
        'services': {}
    }
    
    try:
        # Configurações básicas
        arguments = '-' + config.get('scan_type', DEFAULT_PORT_CONFIG['scan_type'])
        
        # Adicionar detecção de serviço se configurado
        if config.get('service_detection', DEFAULT_PORT_CONFIG['service_detection']):
            arguments += ' -sV'
            # Configurar intensidade da detecção de serviço
            intensity = config.get('service_intensity', DEFAULT_PORT_CONFIG['service_intensity'])
            arguments += f' --version-intensity {intensity}'
        
        # Adicionar scripts NSE
        nse_scripts = config.get('nse_scripts', DEFAULT_PORT_CONFIG['nse_scripts'])
        if nse_scripts:
            script_args = ','.join(nse_scripts) if isinstance(nse_scripts, list) else nse_scripts
            arguments += f' --script={script_args}'
        
        # Adicionar detecção de sistema operacional se configurado (requer root)
        if config.get('os_detection', DEFAULT_PORT_CONFIG['os_detection']):
            arguments += ' -O'
        
        # Configurar timeout
        timeout = config.get('timeout', DEFAULT_PORT_CONFIG['timeout'])
        arguments += f' --max-rtt-timeout {timeout}s'
        
        # Configurar taxa de pacotes (mais baixa para evitar sobrecarregar a rede)
        min_rate = config.get('min_rate', DEFAULT_PORT_CONFIG['min_rate'])
        arguments += f' --min-rate {min_rate}'
        
        # Adicionar argumentos personalizados
        additional_args = config.get('additional_args', DEFAULT_PORT_CONFIG['additional_args'])
        if additional_args:
            arguments += f' {additional_args}'
        
        # Inicializar scanner
        scanner = nmap.PortScanner()
        
        # Determinar portas para escanear
        port_spec = None
        if ports and len(ports) > 0:
            port_spec = ','.join(map(str, ports))
        elif config.get('full_scan', DEFAULT_PORT_CONFIG['full_scan']):
            port_spec = '1-65535'
        else:
            port_spec = ','.join(map(str, config.get('default_ports', DEFAULT_PORT_CONFIG['default_ports'])))
        
        # Executar scan
        logger.debug(f"Executando nmap com argumentos: {arguments}")
        scanner.scan(target, port_spec, arguments)
        
        # Processar resultados
        if target in scanner.all_hosts():
            host_data = scanner[target]
            
            # Coletar informações do sistema operacional
            if 'osmatch' in host_data:
                result['os'] = [{
                    'name': match['name'],
                    'accuracy': match['accuracy'],
                    'line': match.get('line', '')
                } for match in host_data['osmatch']]
            
            # Processar portas e serviços
            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    if port_data['state'] == 'open':
                        result['open_ports'].append(int(port))
                        
                        service_info = {
                            'name': port_data.get('name', ''),
                            'product': port_data.get('product', ''),
                            'version': port_data.get('version', ''),
                            'extrainfo': port_data.get('extrainfo', ''),
                            'cpe': port_data.get('cpe', ''),
                            'state': port_data['state']
                        }
                        
                        # Adicionar resultados de scripts NSE
                        if 'script' in port_data:
                            service_info['scripts'] = port_data['script']
                        
                        result['services'][port] = service_info
            
            # Adicionar informações de scripts NSE a nível de host
            if 'hostscript' in host_data:
                result['host_scripts'] = host_data['hostscript']
        
        return result
    
    except Exception as e:
        logger.error(f"Erro durante scan nmap: {e}")
        return None

def scan_with_naabu(target, config, timeout=120):
    """
    Escaneia um alvo usando naabu (se disponível)
    
    Args:
        target (str): IP ou domínio para escanear
        config (dict): Configurações de escaneamento de portas
        timeout (int): Timeout em segundos
    
    Returns:
        list: Lista de portas abertas encontradas
    """
    open_ports = []
    
    try:
        cmd = ["naabu", "-host", target, "-silent"]
        
        # Configurar portas
        if config.get('full_scan', DEFAULT_PORT_CONFIG['full_scan']):
            cmd.extend(["-p", "1-65535"])
        else:
            default_ports = config.get('default_ports', DEFAULT_PORT_CONFIG['default_ports'])
            port_spec = ','.join(map(str, default_ports))
            cmd.extend(["-p", port_spec])
        
        # Aumentar rate limit para escaneamento mais rápido
        naabu_rate = config.get('naabu_rate', DEFAULT_PORT_CONFIG['naabu_rate'])
        cmd.extend(["-rate", str(naabu_rate)])
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout)
        
        if process.returncode == 0:
            # Naabu retorna uma porta por linha no formato host:porta
            for line in stdout.strip().split('\n'):
                if line and ':' in line:
                    parts = line.strip().split(':')
                    if len(parts) > 1:
                        try:
                            port = int(parts[-1])
                            open_ports.append(port)
                        except ValueError:
                            pass
    
    except Exception as e:
        logger.error(f"Erro no escaneamento com naabu para {target}: {e}")
    
    return sorted(open_ports)

def scan_with_socket(target, ports, config):
    """
    Escaneia um alvo usando socket puro do Python
    
    Args:
        target (str): IP ou domínio para escanear
        ports (list): Lista de portas para escanear
        config (dict): Configurações de escaneamento de portas
    
    Returns:
        list: Lista de portas abertas
    """
    open_ports = []
    socket_timeout = config.get('socket_timeout', DEFAULT_PORT_CONFIG['socket_timeout'])
    socket.setdefaulttimeout(socket_timeout)
    
    # Determinar o endereço IP se for um domínio
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        logger.error(f"Não foi possível resolver o domínio: {target}")
        return open_ports
    
    # Escanear portas
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    
    return sorted(open_ports) 