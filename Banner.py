# -*- coding: utf-8 -*-
"""
===========================================
ZAFOM - Zee's Analyzer For Online Monitoring
Module: Banner
Author: Zeeshan
Version: 2.1
===========================================
"""

from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init(autoreset=True)


def show_banner():
    """Display the ZAFOM ASCII banner with branding."""
    print(Fore.YELLOW + Style.BRIGHT + """
   ███████╗ █████╗ ███████╗ ██████╗ ███╗   ███╗
   ╚══███╔╝██╔══██╗██╔════╝██╔═══██╗████╗ ████║
     ███╔╝ ███████║███████╗██║   ██║██╔████╔██║
    ███╔╝  ██╔══██║██║     ██║   ██║██╔╝    ██║
   ███████╗██║  ██║██       ██████  ██      ██║ 
   ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝
               
           ZAFOM v2.1
  Zee's Analyzer For Online Monitoring
""")
    print(Fore.YELLOW + Style.BRIGHT + " Author  : Zeeshan")
    print(Fore.YELLOW + Style.BRIGHT + " Version : 2.1")
    print(Fore.YELLOW + Style.BRIGHT + " Cyber Security | Network Protocol Analyzer")
    print(Fore.YELLOW + "--------------------------------------------------")
    print(Fore.YELLOW + " Features: Real-time capture, Protocol filtering,")
    print(Fore.YELLOW + "           Export (PCAP/JSON/TXT), HEX viewer,")
    print(Fore.YELLOW + "           Statistics dashboard, Search & Filter")
    print(Fore.YELLOW + "--------------------------------------------------\n")


def get_app_info():
    """Return application metadata."""
    return {
        "name": "ZAFOM",
        "version": "2.1",
        "author": "Zeeshan",
        "description": "Zee's Analyzer For Online Monitoring"
    }