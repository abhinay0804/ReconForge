import random
import time
import sys

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
PURPLE = "\033[95m"
YELLOW = "\033[93m"

COLORS = [RED, GREEN, CYAN, PURPLE, YELLOW]

MAIN_LOGO = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
"""

SUBTITLE = "Your Frontline Port Recon Scanner"

QUOTES = [
    "Scanning the silence...",
    "Recon before exploit.",
    "Find first. Strike later.",
    "Every port tells a story.",
    "Mapping attack surfaces.",
    "Knowledge is the weapon."
]

def type_effect(text, delay=0.001):
    for c in text:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_banner():
    color = random.choice(COLORS)
    quote = random.choice(QUOTES)

    print("\n")
    type_effect(color + BOLD + MAIN_LOGO + RESET, 0.0006)
    print(color + BOLD + "        " + SUBTITLE + RESET)
    print(color + "        " + quote + RESET)
    print("\n")

