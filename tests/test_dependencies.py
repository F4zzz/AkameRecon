#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de teste de dependências
Verifica se todas as bibliotecas Python e ferramentas externas
necessárias estão instaladas e disponíveis no sistema.
"""

import sys
import subprocess
import shutil
import os
from typing import Dict, List, Tuple

# Tentar importar pkg_resources, se falhar, usar importlib.metadata (Python 3.8+)
try:
    import pkg_resources
    HAS_PKG_RESOURCES = True
except ImportError:
    HAS_PKG_RESOURCES = False
    try:
        import importlib.metadata as metadata
    except ImportError:
        print("ERRO: Nem pkg_resources nem importlib.metadata estão disponíveis.")
        print("Instale setuptools com: pip install setuptools")
        sys.exit(1)

# Bibliotecas Python necessárias e suas versões mínimas
REQUIRED_PACKAGES = {
    'requests': '2.25.0',
    'beautifulsoup4': '4.9.0',
    'dnspython': '2.1.0',
    'python-nmap': '0.7.1',
    'tqdm': '4.50.0',
    'pyyaml': '5.4.0',
    'tldextract': '3.1.0',
    'bs4': '0.0.1',  # Parte do beautifulsoup4
    'urllib3': '1.26.0',  # Dependência do requests
    'ipaddress': '1.0.23',  # Para manipulação de IPs
    'colorama': '0.4.6',  # Para colorir output no terminal
    'setuptools': '41.0.0'  # Para pkg_resources
}

# Ferramentas externas necessárias
REQUIRED_TOOLS = {
    'nmap': 'Escaneamento de portas e serviços',
    'dig': 'Consultas DNS avançadas',
    'whatweb': 'Detecção de tecnologias web',
    'httpx': 'Análise de serviços HTTP/HTTPS',
    'naabu': 'Descoberta de portas',
    'subfinder': 'Enumeração de subdomínios'
}

def get_install_command(tool: str) -> str:
    """
    Retorna o comando de instalação para uma ferramenta
    
    Args:
        tool (str): Nome da ferramenta
    
    Returns:
        str: Comando de instalação
    """
    install_commands = {
        'nmap': {
            'apt': 'sudo apt-get install nmap',
            'brew': 'brew install nmap'
        },
        'dig': {
            'apt': 'sudo apt-get install dnsutils',
            'brew': 'brew install bind'
        },
        'whatweb': {
            'apt': 'sudo apt-get install whatweb',
            'brew': 'brew install whatweb'
        },
        'httpx': {
            'apt': 'cd /tmp && wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.9/httpx_1.3.9_linux_amd64.zip && unzip httpx_1.3.9_linux_amd64.zip && sudo mv httpx /usr/local/bin/ && rm -rf httpx_1.3.9_linux_amd64.zip LICENSE.md README.md',
            'brew': 'brew install httpx'
        },
        'naabu': {
            'apt': 'cd /tmp && wget https://github.com/projectdiscovery/naabu/releases/download/v2.3.4/naabu_2.3.4_linux_amd64.zip && unzip naabu_2.3.4_linux_amd64.zip && sudo mv naabu /usr/local/bin/ && rm -rf naabu_2.3.4_linux_amd64.zip LICENSE.md README.md',
            'brew': 'brew install naabu'
        },
        'subfinder': {
            'apt': 'cd /tmp && wget https://github.com/projectdiscovery/subfinder/releases/download/v2.7.1/subfinder_2.7.1_linux_amd64.zip && unzip subfinder_2.7.1_linux_amd64.zip && sudo mv subfinder /usr/local/bin/ && rm -rf subfinder_2.7.1_linux_amd64.zip LICENSE.md README.md',
            'brew': 'brew install subfinder'
        }
    }

    if tool in install_commands:
        if sys.platform == 'darwin':
            return install_commands[tool]['brew']
        else:
            return install_commands[tool]['apt']
    return ''

def check_python_packages() -> List[str]:
    """
    Verifica se todas as bibliotecas Python necessárias estão instaladas
    com as versões mínimas requeridas.
    
    Returns:
        List[str]: Lista de pacotes que precisam ser instalados/atualizados
    """
    missing_packages = []
    
    for package, min_version in REQUIRED_PACKAGES.items():
        try:
            if HAS_PKG_RESOURCES:
                # Usar pkg_resources quando disponível
                try:
                    installed_version = pkg_resources.get_distribution(package).version
                    if pkg_resources.parse_version(installed_version) < pkg_resources.parse_version(min_version):
                        missing_packages.append(f"{package}>={min_version}")
                except pkg_resources.DistributionNotFound:
                    missing_packages.append(f"{package}>={min_version}")
            else:
                # Usar importlib.metadata como alternativa (Python 3.8+)
                try:
                    installed_version = metadata.version(package)
                    # Comparação simples de versão como fallback
                    if parse_version_simple(installed_version) < parse_version_simple(min_version):
                        missing_packages.append(f"{package}>={min_version}")
                except metadata.PackageNotFoundError:
                    missing_packages.append(f"{package}>={min_version}")
        except Exception as e:
            print(f"Erro ao verificar o pacote {package}: {e}")
            missing_packages.append(f"{package}>={min_version}")
    
    return missing_packages

def parse_version_simple(version_str: str) -> List[int]:
    """
    Função simples para parsing de versão sem depender de pkg_resources
    
    Args:
        version_str (str): String de versão (ex: "1.2.3")
    
    Returns:
        List[int]: Lista de componentes da versão como inteiros
    """
    parts = []
    for part in version_str.split('.'):
        try:
            parts.append(int(''.join(c for c in part if c.isdigit())))
        except ValueError:
            parts.append(0)
    return parts

def check_external_tools() -> Dict[str, bool]:
    """
    Verifica se todas as ferramentas externas necessárias estão instaladas
    e disponíveis no PATH do sistema.
    
    Returns:
        Dict[str, bool]: Dicionário com o status de cada ferramenta
    """
    tools_status = {}
    
    for tool in REQUIRED_TOOLS.keys():
        if tool == 'dig':
            # No Windows, dig não é um comando nativo
            if sys.platform == 'win32':
                tools_status[tool] = False
                continue
        
        tools_status[tool] = bool(shutil.which(tool))
    
    return tools_status

def install_python_packages(packages: List[str]) -> bool:
    """
    Instala pacotes Python usando pip
    
    Args:
        packages (List[str]): Lista de pacotes para instalar
    
    Returns:
        bool: True se a instalação foi bem-sucedida
    """
    if not packages:
        return True
        
    print(f"\nInstalando {len(packages)} pacotes Python...")
    
    try:
        cmd = [sys.executable, "-m", "pip", "install"] + packages
        print(f"Executando: {' '.join(cmd)}")
        
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if process.returncode == 0:
            print("✓ Todos os pacotes foram instalados com sucesso!")
            return True
        else:
            print(f"✗ Erro ao instalar pacotes: {process.stderr}")
            return False
    except Exception as e:
        print(f"✗ Erro durante instalação: {e}")
        return False

def install_external_tool(tool: str) -> bool:
    """
    Instala uma ferramenta externa usando o comando apropriado
    
    Args:
        tool (str): Nome da ferramenta para instalar
    
    Returns:
        bool: True se a instalação foi bem-sucedida
    """
    install_cmd = get_install_command(tool)
    
    if not install_cmd:
        print(f"✗ Não foi possível determinar como instalar {tool}")
        return False
    
    print(f"\nInstalando {tool}...")
    print(f"Executando: {install_cmd}")
    
    try:
        if sys.platform == 'darwin' and 'brew' in install_cmd:
            # No macOS, executar com brew normalmente
            process = subprocess.run(install_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        else:
            # No Linux, pode precisar de sudo
            process = subprocess.run(install_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if process.returncode == 0:
            print(f"✓ {tool} instalado com sucesso!")
            return True
        else:
            print(f"✗ Erro ao instalar {tool}: {process.stderr}")
            return False
    except Exception as e:
        print(f"✗ Erro durante instalação de {tool}: {e}")
        return False

def main():
    """
    Função principal que executa a verificação de dependências
    e sugere comandos de instalação quando necessário.
    """
    print("\n=== Verificando dependências do AkameRecon ===\n")
    
    # Verifica pacotes Python
    print("Verificando bibliotecas Python...")
    missing_packages = check_python_packages()
    
    if missing_packages:
        print("\nBibliotecas Python faltando ou desatualizadas:")
        for package in missing_packages:
            print(f"  ✗ {package}")
        
        install_choice = input("\nDeseja instalar as bibliotecas Python faltantes? [S/n]: ").lower()
        if install_choice in ['', 's', 'sim', 'y', 'yes']:
            success = install_python_packages(missing_packages)
            if not success:
                print("\nAlguns pacotes Python não puderam ser instalados. Verifique os erros acima.")
        else:
            print("\nPara instalar manualmente, execute:")
            print(f"pip install {' '.join(missing_packages)}")
    else:
        print("✓ Todas as bibliotecas Python estão instaladas e atualizadas!")
    
    # Verifica ferramentas externas
    print("\nVerificando ferramentas externas...")
    tools_status = check_external_tools()
    
    missing_tools = {tool: desc for tool, desc in REQUIRED_TOOLS.items() 
                    if not tools_status.get(tool, False)}
    
    if missing_tools:
        print("\nFerramentas externas faltando:")
        for tool, desc in missing_tools.items():
            print(f"  ✗ {tool} - {desc}")
        
        install_choice = input("\nDeseja instalar as ferramentas externas faltantes? [S/n]: ").lower()
        if install_choice in ['', 's', 'sim', 'y', 'yes']:
            for tool in missing_tools:
                install_external_tool(tool)
                # Verificar novamente após a instalação
                if shutil.which(tool):
                    print(f"✓ {tool} está agora disponível no sistema")
                else:
                    print(f"✗ {tool} ainda não está disponível no sistema. Verifique erros de instalação ou adicione ao PATH.")
        else:
            print("\nPara instalar manualmente:")
            for tool in missing_tools:
                install_cmd = get_install_command(tool)
                if install_cmd:
                    print(f"\n{tool}:")
                    print(f"  {install_cmd}")
                else:
                    print(f"\n{tool}: Instalação manual necessária. Consulte a documentação.")
    else:
        print("✓ Todas as ferramentas externas estão instaladas!")
    
    # Verifica novamente após instalações
    missing_packages_after = check_python_packages()
    tools_status_after = check_external_tools()
    missing_tools_after = {tool: desc for tool, desc in REQUIRED_TOOLS.items() 
                          if not tools_status_after.get(tool, False)}
    
    if missing_packages_after or missing_tools_after:
        print("\n⚠ Algumas dependências ainda estão faltando!")
        return 1
    else:
        print("\n✓ Todas as dependências estão satisfeitas!")
        return 0

if __name__ == '__main__':
    sys.exit(main()) 