"""
sedf/utils/banner.py - ASCII banner and legal disclaimer for SEDF.
"""

from sedf import __version__, __author__


BANNER = r"""
  ███████╗███████╗██████╗ ███████╗
  ██╔════╝██╔════╝██╔══██╗██╔════╝
  ███████╗█████╗  ██║  ██║█████╗
  ╚════██║██╔══╝  ██║  ██║██╔══╝
  ███████║███████╗██████╔╝██║
  ╚══════╝╚══════╝╚═════╝ ╚═╝

  SSRF Exploitation and Defense Framework
"""

DISCLAIMER = """
  ╔══════════════════════════════════════════════════════════════╗
  ║  LEGAL NOTICE                                                ║
  ║                                                              ║
  ║  This tool is intended for EDUCATIONAL PURPOSES and          ║
  ║  AUTHORIZED PENETRATION TESTING ONLY.                        ║
  ║                                                              ║
  ║  Using this tool against systems without explicit written    ║
  ║  permission from the system owner is ILLEGAL and may         ║
  ║  result in criminal prosecution.                             ║
  ║                                                              ║
  ║  The authors accept NO responsibility for misuse.            ║
  ╚══════════════════════════════════════════════════════════════╝
"""


def print_banner():
    cyan = "\033[36m"
    yellow = "\033[33m"
    reset = "\033[0m"
    print(f"{cyan}{BANNER}{reset}")
    print(f"  Version : {__version__}")
    print(f"  Authors : {__author__}")
    print(f"  Mode    : Security Research / FYP\n")


def print_disclaimer():
    red = "\033[31m"
    reset = "\033[0m"
    print(f"{red}{DISCLAIMER}{reset}")
