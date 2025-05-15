#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de resolução DNS
Resolve domínios para endereços IP e outros registros DNS
usando dnspython e subprocess para ferramentas como 'dig'.
"""

import os
import re
import json
import logging
import ipaddress
import concurrent.futures
import subprocess
import dns.resolver
import dns.rdatatype
from tqdm import tqdm

from utils import helpers

# Configurar logger
logger = logging.getLogger("AkameRecon")

# Valores padrão de configuração mais conservadores
DEFAULT_DNS_CONFIG = {
    'resolvers': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9'],
    'record_types': ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'],
    'concurrent_requests': 5,  # Valor mais baixo para evitar sobrecarga
    'timeout': 5,  # Timeout em segundos para consultas
    'use_dig': False,  # Se deve usar o comando dig
    'max_dig_timeout': 10,  # Timeout para comandos dig
    'try_zone_transfer': False,  # Se deve tentar transferência de zona (potencialmente intrusivo)
    'filter_internal_ips': True  # Se deve filtrar IPs internos
}

def is_internal_ip(ip):
    """
    Verifica se um endereço IP é interno/privado
    
    Args:
        ip (str): Endereço IP para verificar
    
    Returns:
        bool: True se o IP for interno, False caso contrário
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            ip_obj.is_reserved
        )
    except ValueError:
        return False

def filter_internal_ips(ips):
    """
    Filtra IPs internos de uma lista de endereços
    
    Args:
        ips (list): Lista de endereços IP
    
    Returns:
        list: Lista de IPs públicos
    """
    return [ip for ip in ips if not is_internal_ip(ip)]

def resolve_domains(domains, config):
    """
    Resolve uma lista de domínios para seus respectivos IPs e registros DNS
    
    Args:
        domains (list): Lista de domínios para resolver
        config (dict): Configurações da ferramenta
    
    Returns:
        dict: Dicionário com informações DNS para cada domínio
    """
    results = {}
    
    # Obter configuração DNS, com fallback para valores padrão
    dns_config = config.get('dns', {})
    
    # Obter cada configuração com fallback para o valor padrão
    resolvers = dns_config.get('resolvers', DEFAULT_DNS_CONFIG['resolvers'])
    record_types = dns_config.get('record_types', DEFAULT_DNS_CONFIG['record_types'])
    max_workers = dns_config.get('concurrent_requests', DEFAULT_DNS_CONFIG['concurrent_requests'])
    dns_timeout = dns_config.get('timeout', DEFAULT_DNS_CONFIG['timeout'])
    use_dig = dns_config.get('use_dig', DEFAULT_DNS_CONFIG['use_dig'])
    dig_timeout = dns_config.get('max_dig_timeout', DEFAULT_DNS_CONFIG['max_dig_timeout'])
    try_zone_transfer = dns_config.get('try_zone_transfer', DEFAULT_DNS_CONFIG['try_zone_transfer'])
    filter_internal = dns_config.get('filter_internal_ips', DEFAULT_DNS_CONFIG['filter_internal_ips'])
    
    # Registrar configurações usadas para depuração
    logger.debug(f"Configuração DNS: max_workers={max_workers}, timeout={dns_timeout}s, use_dig={use_dig}")
    
    if not domains:
        logger.warning("Nenhum domínio para resolver")
        return results
    
    logger.info(f"Resolvendo registros DNS para {len(domains)} domínios")
    
    # Função para resolver um único domínio
    def resolve_domain(domain):
        domain_data = {
            'domain': domain,
            'ips': [],
            'ipv6': [],
            'cname': None,
            'mx': [],
            'ns': [],
            'txt': [],
            'is_resolvable': False
        }
        
        # Usar dnspython para resolução básica
        for record_type in record_types:
            try:
                answers = resolve_dns_record(domain, record_type, resolvers, dns_timeout)
                
                if record_type == 'A':
                    ips = [str(answer) for answer in answers]
                    if filter_internal:
                        ips = filter_internal_ips(ips)
                    domain_data['ips'] = ips
                    if ips:
                        domain_data['is_resolvable'] = True
                elif record_type == 'AAAA':
                    ipv6_addrs = [str(answer) for answer in answers]
                    if filter_internal:
                        ipv6_addrs = filter_internal_ips(ipv6_addrs)
                    domain_data['ipv6'] = ipv6_addrs
                    if ipv6_addrs:
                        domain_data['is_resolvable'] = True
                elif record_type == 'CNAME':
                    if answers:
                        domain_data['cname'] = str(answers[0]).rstrip('.')
                        domain_data['is_resolvable'] = True
                elif record_type == 'MX':
                    domain_data['mx'] = [f"{answer.preference} {str(answer.exchange).rstrip('.')}" for answer in answers]
                elif record_type == 'NS':
                    domain_data['ns'] = [str(answer).rstrip('.') for answer in answers]
                elif record_type == 'TXT':
                    domain_data['txt'] = [answer.strings[0].decode('utf-8', errors='ignore') for answer in answers]
            except Exception as e:
                if "NXDOMAIN" not in str(e):  # Ignorar domínios que não existem
                    logger.debug(f"Erro ao resolver {record_type} para {domain}: {e}")
        
        # Se solicitado, usar dig para informações mais detalhadas
        if use_dig and helpers.is_command_available('dig'):
            try:
                domain_data['dig_info'] = use_dig(domain, timeout=dig_timeout, try_zone_transfer=try_zone_transfer)
            except Exception as e:
                logger.debug(f"Erro ao executar dig para {domain}: {e}")
        
        return domain, domain_data
    
    # Resolver domínios em paralelo - limitando o número de workers para evitar sobrecarga
    safe_max_workers = min(max_workers, 10)  # Nunca exceder 10 workers, mesmo se config for maior
    with concurrent.futures.ThreadPoolExecutor(max_workers=safe_max_workers) as executor:
        future_to_domain = {executor.submit(resolve_domain, domain): domain for domain in domains}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_domain), 
                         total=len(domains), desc="Resolução DNS", ncols=80):
            try:
                domain, result = future.result()
                # Incluir apenas domínios que foram resolvidos com sucesso
                if result and result['is_resolvable']:
                    results[domain] = result
            except Exception as e:
                logger.error(f"Erro ao processar resultado DNS: {e}")
    
    logger.info(f"Resolvidos {len(results)} domínios com sucesso")
    return results

def resolve_dns_record(domain, record_type, resolvers, timeout=3):
    """
    Resolve um tipo específico de registro DNS para um domínio
    
    Args:
        domain (str): Domínio para resolver
        record_type (str): Tipo de registro (A, AAAA, CNAME, etc.)
        resolvers (list): Lista de servidores DNS para usar
        timeout (int): Tempo limite em segundos para a consulta
    
    Returns:
        list: Lista de respostas do tipo solicitado
    """
    resolver = dns.resolver.Resolver()
    
    # Usar um resolver aleatório para distribuir consultas
    resolver.nameservers = [resolvers[hash(domain + record_type) % len(resolvers)]]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    try:
        answers = resolver.resolve(domain, record_type)
        return answers
    except Exception:
        return []

def use_dig(domain, timeout=5, try_zone_transfer=False):
    """
    Usa a ferramenta dig para obter informações DNS detalhadas
    
    Args:
        domain (str): Domínio para consultar
        timeout (int): Tempo limite em segundos
        try_zone_transfer (bool): Se deve tentar transferência de zona
    
    Returns:
        dict: Informações obtidas via dig
    """
    result = {
        'all': {},
        'soa': None,
        'zone_transfer': None
    }
    
    # Configurar comando base
    dig_cmd = ["dig", "+short"]
    
    # Executar para cada tipo de registro
    for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']:
        try:
            cmd = dig_cmd + [domain, record_type]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode == 0 and stdout.strip():
                if record_type == 'SOA':
                    result['soa'] = stdout.strip()
                else:
                    result['all'][record_type] = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        except Exception as e:
            logger.debug(f"Erro em dig {record_type} para {domain}: {e}")
    
    # Tentar transferência de zona (AXFR) apenas se permitido na configuração
    if try_zone_transfer:
        ns_servers = result['all'].get('NS', [])
        if ns_servers and len(ns_servers) > 0:
            for ns in ns_servers:
                try:
                    axfr_cmd = ["dig", "axfr", domain, f"@{ns}"]
                    process = subprocess.Popen(
                        axfr_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    
                    stdout, stderr = process.communicate(timeout=timeout)
                    
                    if process.returncode == 0 and "Transfer failed" not in stdout:
                        result['zone_transfer'] = {
                            'ns': ns,
                            'result': stdout.strip()
                        }
                        break  # Se conseguirmos uma transferência, paramos
                except Exception:
                    pass  # Ignora erros na tentativa de transferência de zona
    
    return result 