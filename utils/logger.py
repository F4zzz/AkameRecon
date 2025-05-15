#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de log para AkameRecon
Implementa um sistema de log colorido e formatado.
"""

import logging
import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Classe para formatar logs com cores"""
    
    COLORS = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, Fore.WHITE)
        format_str = f"{log_color}[%(asctime)s] [%(levelname)s] %(message)s{Style.RESET_ALL}"
        formatter = logging.Formatter(format_str, datefmt="%H:%M:%S")
        return formatter.format(record)

def setup_logger(level=logging.INFO, log_file=None):
    """Configura e retorna o logger"""
    logger = logging.getLogger("AkameRecon")
    logger.setLevel(level)
    
    # Remover handlers existentes
    if logger.handlers:
        logger.handlers.clear()
    
    # Handler de console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    # Handler de arquivo (opcional)
    if log_file:
        # Criar diretório de logs se não existir
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_format = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

def get_banner(text, type="info"):
    """Retorna um texto formatado como banner"""
    colors = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED
    }
    color = colors.get(type, Fore.WHITE)
    banner = f"\n{color}{'=' * 70}\n"
    banner += f"{color}    {text}\n"
    banner += f"{color}{'=' * 70}{Style.RESET_ALL}\n"
    return banner 