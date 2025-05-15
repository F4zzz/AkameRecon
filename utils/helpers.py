#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Funções auxiliares para AkameRecon
Contém utilitários compartilhados por múltiplos módulos do projeto.
"""

import os
import re
import json
import csv
import socket
import ipaddress
import subprocess
import requests
import random
import time
import concurrent.futures
from tqdm import tqdm
from urllib.parse import urlparse

def is_valid_domain(domain):
    """Verifica se o domínio é válido"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_ip(ip):
    """Verifica se o endereço IP é válido"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def normalize_url(url):
    """Normaliza uma URL para o formato http(s)://dominio.com/"""
    if not url:
        return None
    
    # Adiciona protocolo se não existir
    if not url.startswith('http'):
        url = f'http://{url}'
    
    # Garante que a URL termina com '/'
    if not url.endswith('/'):
        url = f'{url}/'
    
    return url

def extract_domain_from_url(url):
    """Extrai o domínio de uma URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        return domain
    except Exception:
        return None

def load_wordlist(wordlist_path):
    """Carrega uma wordlist a partir de um arquivo"""
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist não encontrada: {wordlist_path}")
    
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def save_json(data, output_file):
    """Salva dados em formato JSON"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def save_csv(data, output_file, headers=None):
    """Salva dados em formato CSV"""
    if not data:
        return False
    
    # Se headers não for fornecido, tenta extrair do primeiro item
    if not headers and isinstance(data[0], dict):
        headers = list(data[0].keys())
    
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        
        # Escreve o cabeçalho
        if headers:
            writer.writerow(headers)
        
        # Escreve os dados
        for item in data:
            if isinstance(item, dict):
                writer.writerow([item.get(h, '') for h in headers])
            else:
                writer.writerow(item)
    
    return True

def random_user_agent():
    """Retorna um User-Agent aleatório"""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"
    ]
    return random.choice(user_agents)

def run_cmd(command, shell=False):
    """Executa um comando no sistema e retorna o resultado"""
    try:
        if isinstance(command, str) and not shell:
            command = command.split()
        
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate()
        return {
            'success': process.returncode == 0,
            'stdout': stdout,
            'stderr': stderr,
            'returncode': process.returncode
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'returncode': 1
        }

def run_async(func, items, max_workers=10, desc="Processando"):
    """Executa uma função de forma assíncrona usando ThreadPoolExecutor"""
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submete todas as tarefas e mapeia para seu future
        future_to_item = {executor.submit(func, item): item for item in items}
        
        # Acompanha o progresso com tqdm
        for future in tqdm(concurrent.futures.as_completed(future_to_item), 
                         total=len(items), desc=desc, ncols=80):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Erro: {e}")
    
    return results

def handle_rate_limiting(response, sleep_time=2):
    """Gerencia rate-limiting em APIs"""
    if response.status_code == 429:
        retry_after = response.headers.get('Retry-After')
        if retry_after:
            try:
                sleep_time = int(retry_after)
            except ValueError:
                pass
        
        time.sleep(sleep_time)
        return True
    return False

def is_command_available(command):
    """Verifica se um comando está disponível no sistema"""
    try:
        # Para Windows
        if os.name == 'nt':
            result = subprocess.run(f"where {command}", shell=True, 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        # Para Unix/Linux/Mac
        else:
            result = subprocess.run(f"which {command}", shell=True, 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
    except Exception:
        return False 