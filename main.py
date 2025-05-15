#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AkameRecon - Ferramenta de reconhecimento para pentest

Esta ferramenta automatiza o processo de reconhecimento de domínios para
auxiliar pentests, incluindo descoberta de subdomínios, resolução DNS,
verificação de portas, fingerprinting e outros.
"""

import os
import sys
import argparse
import yaml
import time
import logging
from datetime import datetime
import subprocess

# Importar módulos internos
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core import domain_enum, dns_tools, port_scanner, web_services
from utils import logger, helpers
from core import report

def banner():
    """Exibe o banner da ferramenta"""
    print("""
    ▄▄▄       ██ ▄█▀▄▄▄       ███▄ ▄███▓▓█████     ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █ 
    ▒████▄     ██▄█▒▒████▄    ▓██▒▀█▀ ██▒▓█   ▀    ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ 
    ▒██  ▀█▄  ▓███▄░▒██  ▀█▄  ▓██    ▓██░▒███      ▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒
    ░██▄▄▄▄██ ▓██ █▄░██▄▄▄▄██ ▒██    ▒██ ▒▓█  ▄    ▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒
    ▓█   ▓██▒▒██▒ █▄▓█   ▓██▒▒██▒   ░██▒░▒████▒   ░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░
    ▒▒   ▓▒█░▒ ▒▒ ▓▒▒▒   ▓▒█░░ ▒░   ░  ░░░ ▒░ ░   ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
    ▒   ▒▒ ░░ ░▒ ▒░ ▒   ▒▒ ░░  ░      ░ ░ ░  ░     ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░
    ░   ▒   ░ ░░ ░  ░   ▒   ░      ░      ░        ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░ 
        ░  ░░  ░        ░  ░       ░      ░  ░      ░        ░  ░░ ░          ░ ░           ░ 
                                                                 ░                            
                               [ By: F4zzz | v1.0 ]
    """)

def load_config():
    """Carrega as configurações do arquivo config.yaml"""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml'), 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Erro ao carregar configurações: {e}")
        return {}

def setup_output_directory(domain):
    """Cria a estrutura de pastas para saída de resultados"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                             'output', f"{domain}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def parse_arguments():
    """Configura e faz o parse dos argumentos da linha de comando"""
    parser = argparse.ArgumentParser(description='AkameRecon - Ferramenta de reconhecimento para pentest')
    parser.add_argument('-d', '--domain', type=str, required=True, help='Domínio alvo')
    parser.add_argument('--full', action='store_true', help='Executa reconhecimento completo')
    parser.add_argument('--passive', action='store_true', help='Somente técnicas passivas (OSINT)')
    parser.add_argument('--active', action='store_true', help='Somente técnicas ativas (DNS, portas)')
    parser.add_argument('--report', action='store_true', help='Gera relatório detalhado em JSON/CSV')
    parser.add_argument('-o', '--output', type=str, help='Diretório de saída personalizado')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose para mais detalhes')
    parser.add_argument('--auto', action='store_true', help='Modo automático sem interação do usuário')
    return parser.parse_args()

def print_scan_config(config):
    """
    Exibe uma tabela com as configurações do scan
    
    Args:
        config (dict): Configurações carregadas
    """
    print("\n=== Configurações do Scan ===\n")
    
    # Configurações de DNS
    dns_config = config.get('dns', {})
    print("DNS:")
    print(f"├── Resolvers: {', '.join(dns_config.get('resolvers', ['8.8.8.8', '8.8.4.4']))}")
    print(f"├── Record Types: {', '.join(dns_config.get('record_types', ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']))}")
    print(f"├── Threads: {dns_config.get('concurrent_requests', 5)}")
    print(f"└── Timeout: {dns_config.get('timeout', 5)}s\n")
    
    # Configurações de Enumeração de Subdomínios
    subdomain_config = config.get('subdomain_enum', {})
    print("Enumeração de Subdomínios:")
    print(f"├── Subfinder: {'✓' if subdomain_config.get('use_subfinder', True) else '✗'}")
    print(f"├── Bruteforce: {'✓' if subdomain_config.get('use_bruteforce', True) else '✗'}")
    print(f"├── Wordlist: {subdomain_config.get('wordlist_path', 'utils/wordlists/mini.txt')}")
    print(f"├── Threads: {subdomain_config.get('max_bruteforce_workers', 5)}")
    print(f"└── Timeout: {subdomain_config.get('bruteforce_timeout', 2)}s\n")
    
    # Configurações de Port Scan
    port_config = config.get('port_scan', {})
    print("Port Scan:")
    print(f"├── Nmap Type: {port_config.get('scan_type', '-sT')}")
    print(f"├── Service Detection: {'✓' if port_config.get('service_detection', True) else '✗'}")
    print(f"├── NSE Scripts: {', '.join(port_config.get('nse_scripts', ['banner,http-title']))}")
    print(f"├── Threads: {port_config.get('threads', 5)}")
    print(f"└── Timeout: {port_config.get('timeout', 5)}s\n")
    
    # Configurações de Web
    web_config = config.get('web_scan', {})
    print("Web Scan:")
    print(f"├── WhatWeb: {'✓' if web_config.get('tech_detection', True) else '✗'}")
    print(f"├── Follow Redirects: {'✓' if web_config.get('follow_redirects', True) else '✗'}")
    print(f"├── Screenshot: {'✓' if web_config.get('screenshot', False) else '✗'}")
    print(f"├── Threads: {web_config.get('threads', 5)}")
    print(f"└── Timeout: {web_config.get('timeout', 8)}s\n")

def ask_confirmation(message, auto=False):
    """
    Solicita confirmação do usuário para continuar
    
    Args:
        message (str): Mensagem a ser exibida
        auto (bool): Se True, retorna True sem perguntar
    
    Returns:
        str: 'continue', 'skip' ou 'stop'
    """
    if auto:
        return 'continue'
    
    while True:
        choice = input(f"\n{message}\n[C]ontinue/[S]kip/St[o]p? ").lower()
        if choice in ['c', 'continue']:
            return 'continue'
        elif choice in ['s', 'skip']:
            return 'skip'
        elif choice in ['o', 'stop']:
            return 'stop'
        print("Opção inválida. Use C para continuar, S para pular ou O para parar.")

def main():
    """Função principal do programa"""
    banner()
    args = parse_arguments()
    
    # Configurar logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log = logger.setup_logger(log_level)
    
    # Carregar configurações
    config = load_config()
    
    # Exibir configurações do scan
    print_scan_config(config)
    
    # Configurar diretório de saída
    output_dir = args.output if args.output else setup_output_directory(args.domain)
    log.info(f"Resultados serão salvos em: {output_dir}")
    
    # Dicionário para armazenar resultados
    results = {
        'domain': args.domain,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'subdomains': [],
        'dns_records': {},
        'open_ports': {},
        'web_services': {}
    }
    
    # Enumerar subdomínios
    if args.full or args.passive:
        choice = ask_confirmation(
            f"Iniciando enumeração de subdomínios para {args.domain}...",
            args.auto
        )
        if choice == 'stop':
            log.info("Operação interrompida pelo usuário.")
            sys.exit(0)
        elif choice == 'continue':
            results['subdomains'] = domain_enum.enumerate_subdomains(args.domain, config)
            log.info(f"Encontrados {len(results['subdomains'])} subdomínios")
    
    # Resolver DNS e verificar portas
    if args.full or args.active:
        if results['subdomains'] or args.domain:
            targets = results['subdomains'] if results['subdomains'] else [args.domain]
            
            # Resolver DNS
            choice = ask_confirmation(
                f"Iniciando resolução DNS para {len(targets)} domínios...",
                args.auto
            )
            if choice == 'stop':
                log.info("Operação interrompida pelo usuário.")
                sys.exit(0)
            elif choice == 'continue':
                log.info("Iniciando resolução DNS...")
                results['dns_records'] = dns_tools.resolve_domains(targets, config)
            
            # Escanear portas
            ips = [ip for domain_data in results['dns_records'].values() 
                   for ip in domain_data.get('ips', [])]
            choice = ask_confirmation(
                f"Iniciando escaneamento de portas para {len(ips)} IPs...",
                args.auto
            )
            if choice == 'stop':
                log.info("Operação interrompida pelo usuário.")
                sys.exit(0)
            elif choice == 'continue':
                log.info("Iniciando escaneamento de portas...")
                results['open_ports'] = port_scanner.scan_ports(ips, config)
            
            # Verificar serviços web
            http_targets = []
            for domain in targets:
                for port in [80, 443, 8080, 8443]:
                    http_targets.append((domain, port))
            
            choice = ask_confirmation(
                f"Iniciando verificação de serviços web em {len(http_targets)} alvos...",
                args.auto
            )
            if choice == 'stop':
                log.info("Operação interrompida pelo usuário.")
                sys.exit(0)
            elif choice == 'continue':
                log.info("Identificando serviços web...")
                results['web_services'] = web_services.check_web_services(
                    http_targets, 
                    config,
                    dns_results=results['dns_records'],
                    port_results=results['open_ports']
                )
    
    # Gerar relatório
    if args.report or args.full:
        choice = ask_confirmation(
            "Gerando relatório detalhado...",
            args.auto
        )
        if choice == 'stop':
            log.info("Operação interrompida pelo usuário.")
            sys.exit(0)
        elif choice == 'continue':
            log.info("Gerando relatório...")
            report.generate_report(results, output_dir)
    
    # Informar que o reconhecimento foi concluído
    log.info(f"Reconhecimento concluído. Resultados salvos em {output_dir}")
    
    # Opção para executar o Nuclei após o reconhecimento e geração do relatório
    if results['web_services']:
        # Extrair URLs para análise com Nuclei
        web_urls = []
        for target, data in results['web_services'].items():
            if data.get('url'):
                web_urls.append(data.get('url'))
        
        if web_urls:
            # Sempre perguntar sobre o Nuclei, mesmo no modo automático
            nuclei_choice = input("\nDeseja executar o Nuclei para varredura de vulnerabilidades? [S/n]: ").lower()
            
            if nuclei_choice in ['', 's', 'sim', 'y', 'yes']:
                # Configurações do Nuclei
                nuclei_config = config.get('nuclei', {})
                templates_path = nuclei_config.get('templates_path', '~/nuclei-templates/')
                severity = nuclei_config.get('severity', 'low,medium,high,critical')
                rate_limit = nuclei_config.get('rate_limit', 150)
                
                # Comando Nuclei para cada URL
                for url in web_urls:
                    log.info(f"Executando Nuclei em: {url}")
                    
                    try:
                        # Construir comando do Nuclei
                        nuclei_cmd = [
                            "nuclei",
                            "-u", url,
                            "-t", os.path.expanduser(templates_path),
                            "-severity", severity,
                            "-rate-limit", str(rate_limit)
                        ]
                        
                        # Adicionar flags extras se configuradas
                        if nuclei_config.get('additional_flags'):
                            for flag in nuclei_config.get('additional_flags'):
                                nuclei_cmd.append(flag)
                        
                        # Executar Nuclei
                        nuclei_output_file = os.path.join(output_dir, f"nuclei_{url.replace('://', '_').replace('/', '_').replace(':', '_')}.txt")
                        nuclei_cmd.extend(["-o", nuclei_output_file])
                        
                        print(f"Executando: {' '.join(nuclei_cmd)}")
                        process = subprocess.run(nuclei_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        
                        if process.returncode == 0:
                            log.info(f"Análise Nuclei concluída para {url}. Resultados salvos em: {nuclei_output_file}")
                        else:
                            log.error(f"Erro ao executar Nuclei: {process.stderr}")
                    except Exception as e:
                        log.error(f"Erro ao executar Nuclei: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperação interrompida pelo usuário.")
        sys.exit(1)
    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1) 