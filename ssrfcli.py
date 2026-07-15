#!/usr/bin/env python3
"""
SSRF Exploitation and Defense Framework (SEDF)
Main entry point

WARNING: This tool is for educational and authorized penetration testing ONLY.
Unauthorized use against systems you do not own or have explicit permission to test
is illegal and unethical. The authors are not responsible for misuse.
"""

import sys
import os

# Ensure the package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sedf.cli import main

if __name__ == "__main__":
    main()
