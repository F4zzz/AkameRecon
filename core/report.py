#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de geração de relatórios
Gera relatórios detalhados dos resultados do reconhecimento
em diferentes formatos (JSON, TXT, etc).
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List

from utils import helpers

# Configurar logger
logger = logging.getLogger("AkameRecon")

class Report:
    """Classe para geração de relatórios"""
    
    def __init__(self, target_domain: str, output_dir: str, config: Dict[str, Any]):
        """
        Inicializa o gerador de relatórios
    
    Args:
            target_domain (str): Domínio alvo
            output_dir (str): Diretório para salvar relatórios
            config (dict): Configurações da ferramenta
        """
        self.target_domain = target_domain
        self.output_dir = output_dir
        self.report_config = config.get('report', {})
        
        # Estrutura base do relatório
        self.data = {
            'metadata': {
                'target_domain': target_domain,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'tool_version': '1.0',
                'config_used': config
            },
            'summary': {
                'total_subdomains': 0,
                'total_ips': 0,
                'total_ports': 0,
                'total_web_services': 0,
                'total_vulnerabilities': 0
            },
            'subdomains': {
                'total': 0,
                'items': [],
                'sources': {
                    'passive': [],
                    'active': [],
                    'bruteforce': []
                }
            },
            'dns_records': {
                'total': 0,
                'items': {},
                'statistics': {
                    'total_a_records': 0,
                    'total_aaaa_records': 0,
                    'total_cname_records': 0,
                    'total_mx_records': 0,
                    'total_ns_records': 0,
                    'total_txt_records': 0
                }
            },
            'network': {
                'total_ips': 0,
                'total_ports': 0,
                'items': {},
                'statistics': {
                    'top_ports': [],
                    'top_services': [],
                    'os_detection': []
                }
            },
            'web_services': {
                'total': 0,
                'items': {},
                'statistics': {
                    'response_codes': {},
                    'servers': {},
                    'technologies': {
                        'cms': {},
                        'frameworks': {},
                        'languages': {},
                        'javascript': {},
                        'analytics': {},
                        'others': {}
                    }
                }
            },
            'security': {
                'certificates': [],
                'waf_detection': {},
                'vulnerabilities': [],
                'interesting_findings': []
            }
        }
    
    def add_subdomains(self, subdomains: List[str], source: str = 'passive') -> None:
        """
        Adiciona subdomínios ao relatório
        
        Args:
            subdomains (list): Lista de subdomínios
            source (str): Fonte dos subdomínios (passive, active, bruteforce)
        """
        if not subdomains:
            return
        
        # Atualizar lista de subdomínios
        self.data['subdomains']['items'].extend(subdomains)
        self.data['subdomains']['items'] = list(set(self.data['subdomains']['items']))
        self.data['subdomains']['total'] = len(self.data['subdomains']['items'])
        
        # Registrar fonte
        if source not in self.data['subdomains']['sources']:
            self.data['subdomains']['sources'][source] = []
        self.data['subdomains']['sources'][source].extend(subdomains)
        
        # Atualizar sumário
        self.data['summary']['total_subdomains'] = self.data['subdomains']['total']
    
    def add_dns_records(self, dns_records: Dict[str, Any]) -> None:
        """
        Adiciona registros DNS ao relatório
    
    Args:
            dns_records (dict): Dicionário com registros DNS
        """
        if not dns_records:
            return
        
        # Atualizar registros DNS
        self.data['dns_records']['items'].update(dns_records)
        self.data['dns_records']['total'] = len(dns_records)
        
        # Calcular estatísticas
        stats = self.data['dns_records']['statistics']
        for domain_data in dns_records.values():
            if domain_data.get('ips'):
                stats['total_a_records'] += len(domain_data['ips'])
            if domain_data.get('ipv6'):
                stats['total_aaaa_records'] += len(domain_data['ipv6'])
            if domain_data.get('cname'):
                stats['total_cname_records'] += 1
            if domain_data.get('mx'):
                stats['total_mx_records'] += len(domain_data['mx'])
            if domain_data.get('ns'):
                stats['total_ns_records'] += len(domain_data['ns'])
            if domain_data.get('txt'):
                stats['total_txt_records'] += len(domain_data['txt'])
        
        # Atualizar sumário
        total_ips = sum(len(data.get('ips', [])) + len(data.get('ipv6', [])) 
                       for data in dns_records.values())
        self.data['summary']['total_ips'] = total_ips
    
    def add_port_scan(self, port_scan_results: Dict[str, Any]) -> None:
        """
        Adiciona resultados do scan de portas ao relatório
    
    Args:
            port_scan_results (dict): Resultados do escaneamento de portas
        """
        if not port_scan_results:
            return
        
        # Atualizar resultados de rede
        self.data['network']['items'].update(port_scan_results)
        
        # Calcular estatísticas
        port_count = 0
        port_stats = {}
        service_stats = {}
        os_stats = []
        
        for host_data in port_scan_results.values():
            if 'open_ports' in host_data:
                port_count += len(host_data['open_ports'])
                
                # Contar portas
                for port in host_data['open_ports']:
                    port_stats[port] = port_stats.get(port, 0) + 1
                
                # Contar serviços
                if 'services' in host_data:
                    for port, service_info in host_data['services'].items():
                        service_name = service_info.get('name', 'unknown')
                        service_stats[service_name] = service_stats.get(service_name, 0) + 1
                
                # Coletar detecção de SO
                if 'os' in host_data:
                    os_stats.extend(host_data['os'])
        
        # Atualizar estatísticas
        self.data['network']['total_ports'] = port_count
        self.data['network']['statistics']['top_ports'] = sorted(
            port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        self.data['network']['statistics']['top_services'] = sorted(
            service_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        self.data['network']['statistics']['os_detection'] = os_stats
        
        # Atualizar sumário
        self.data['summary']['total_ports'] = port_count
    
    def add_web_services(self, web_results: Dict[str, Any]) -> None:
        """
        Adiciona resultados da análise de serviços web ao relatório
        
        Args:
            web_results (dict): Resultados da análise de serviços web
        """
        if not web_results:
            return
        
        # Atualizar resultados web
        self.data['web_services']['items'].update(web_results)
        self.data['web_services']['total'] = len(web_results)
        
        # Calcular estatísticas
        stats = self.data['web_services']['statistics']
        tech_stats = stats['technologies']
        
        for service_data in web_results.values():
            # Contar códigos de resposta
            status_code = service_data.get('status_code')
            if status_code:
                stats['response_codes'][status_code] = stats['response_codes'].get(status_code, 0) + 1
            
            # Contar servidores web
            server = service_data.get('server')
            if server:
                stats['servers'][server] = stats['servers'].get(server, 0) + 1
            
            # Contar tecnologias
            if 'cms' in service_data and service_data['cms']:
                cms_name = service_data['cms'].split()[0]  # Remover versão
                tech_stats['cms'][cms_name] = tech_stats['cms'].get(cms_name, 0) + 1
            
            if 'frameworks' in service_data:
                for framework in service_data['frameworks']:
                    tech_stats['frameworks'][framework] = tech_stats['frameworks'].get(framework, 0) + 1
            
            if 'javascript' in service_data:
                for js_lib in service_data['javascript']:
                    tech_stats['javascript'][js_lib] = tech_stats['javascript'].get(js_lib, 0) + 1
            
            if 'analytics' in service_data:
                for analytics in service_data['analytics']:
                    tech_stats['analytics'][analytics] = tech_stats['analytics'].get(analytics, 0) + 1
            
            if 'technologies' in service_data:
                for tech in service_data['technologies']:
                    tech_stats['others'][tech] = tech_stats['others'].get(tech, 0) + 1
        
        # Atualizar sumário
        self.data['summary']['total_web_services'] = self.data['web_services']['total']
    
    def add_security_findings(self, findings: Dict[str, Any]) -> None:
        """
        Adiciona descobertas de segurança ao relatório
        
        Args:
            findings (dict): Descobertas de segurança
        """
        if not findings:
            return
        
        # Adicionar certificados SSL
        if 'certificates' in findings:
            self.data['security']['certificates'].extend(findings['certificates'])
        
        # Adicionar detecção de WAF
        if 'waf' in findings:
            self.data['security']['waf_detection'].update(findings['waf'])
        
        # Adicionar vulnerabilidades
        if 'vulnerabilities' in findings:
            self.data['security']['vulnerabilities'].extend(findings['vulnerabilities'])
            self.data['summary']['total_vulnerabilities'] = len(findings['vulnerabilities'])
        
        # Adicionar outras descobertas interessantes
        if 'interesting' in findings:
            self.data['security']['interesting_findings'].extend(findings['interesting'])
    
    def save_report(self) -> None:
        """
        Salva o relatório final em diferentes formatos
        """
        # Atualizar timestamp de término
        self.data['metadata']['end_time'] = datetime.now().isoformat()
        
        # Criar diretório de relatórios se não existir
        report_dir = os.path.join(self.output_dir, 'reports')
        os.makedirs(report_dir, exist_ok=True)
        
        # Salvar relatório em JSON
        json_file = os.path.join(report_dir, f"{self.target_domain}_report.json")
        with open(json_file, 'w') as f:
            json.dump(self.data, f, indent=4)
        logger.info(f"Relatório JSON salvo em: {json_file}")
        
        # Salvar relatório em TXT
        txt_file = os.path.join(report_dir, f"{self.target_domain}_report.txt")
        self._save_txt_report(txt_file)
        logger.info(f"Relatório TXT salvo em: {txt_file}")
        
        # Retornar caminho dos arquivos salvos
        return {
            'json': json_file,
            'txt': txt_file
        }
    
    def _save_txt_report(self, filename: str) -> None:
        """
        Salva o relatório em formato texto
    
    Args:
            filename (str): Nome do arquivo para salvar
        """
        with open(filename, 'w') as f:
            f.write(f"AkameRecon - Relatório de Reconhecimento\n")
            f.write(f"{'='*50}\n\n")
            
            # Metadata
            f.write(f"Alvo: {self.data['metadata']['target_domain']}\n")
            f.write(f"Data Início: {self.data['metadata']['start_time']}\n")
            f.write(f"Data Fim: {self.data['metadata']['end_time']}\n\n")
            
            # Sumário
            f.write("Sumário\n")
            f.write(f"{'-'*30}\n")
            f.write(f"Total de Subdomínios: {self.data['summary']['total_subdomains']}\n")
            f.write(f"Total de IPs: {self.data['summary']['total_ips']}\n")
            f.write(f"Total de Portas: {self.data['summary']['total_ports']}\n")
            f.write(f"Total de Serviços Web: {self.data['summary']['total_web_services']}\n")
            f.write(f"Total de Vulnerabilidades: {self.data['summary']['total_vulnerabilities']}\n\n")
            
            # Subdomínios
            if self.data['subdomains']['items']:
                f.write("Subdomínios Encontrados\n")
                f.write(f"{'-'*30}\n")
                for subdomain in sorted(self.data['subdomains']['items']):
                    f.write(f"- {subdomain}\n")
                f.write("\n")
            
            # Serviços Web
            if self.data['web_services']['items']:
                f.write("Serviços Web\n")
                f.write(f"{'-'*30}\n")
                for target, service_data in self.data['web_services']['items'].items():
                    f.write(f"\n{target}:\n")
                    f.write(f"  Status: {service_data.get('status_code')}\n")
                    f.write(f"  Servidor: {service_data.get('server', 'N/A')}\n")
                    if service_data.get('technologies'):
                        f.write(f"  Tecnologias: {', '.join(service_data['technologies'])}\n")
            
            # Vulnerabilidades
            if self.data['security']['vulnerabilities']:
                f.write("\nVulnerabilidades Encontradas\n")
                f.write(f"{'-'*30}\n")
                for vuln in self.data['security']['vulnerabilities']:
                    f.write(f"\n- {vuln['title']}\n")
                    f.write(f"  Severidade: {vuln.get('severity', 'N/A')}\n")
                    f.write(f"  URL: {vuln.get('url', 'N/A')}\n")

def generate_report(results: Dict[str, Any], output_dir: str) -> Dict[str, str]:
    """
    Função wrapper para gerar relatório a partir dos resultados do reconhecimento.
    Esta função é chamada pelo main.py.
    
    Args:
        results (dict): Resultados do reconhecimento
        output_dir (str): Diretório para salvar o relatório
    
    Returns:
        dict: Caminhos dos arquivos de relatório gerados
    """
    target_domain = results.get('domain', 'unknown')
    config = results.get('config', {})
    
    # Criar instância do relatório
    report = Report(target_domain, output_dir, config)
    
    # Adicionar resultados ao relatório
    if 'subdomains' in results and results['subdomains']:
        report.add_subdomains(results['subdomains'], 'combined')
    
    if 'dns_records' in results and results['dns_records']:
        report.add_dns_records(results['dns_records'])
    
    if 'open_ports' in results and results['open_ports']:
        report.add_port_scan(results['open_ports'])
    
    if 'web_services' in results and results['web_services']:
        report.add_web_services(results['web_services'])
    
    # Salvar e retornar caminhos dos relatórios
    return report.save_report() 