"""
Recon47 — Console Output Utilities
Author: Munia936
"""
import sys
import time

R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DM = "\033[2m"    # dim
B  = "\033[1m"    # bold
M  = "\033[95m"   # magenta
RS = "\033[0m"    # reset

def banner():
    print(f"""{C}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗███████╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██║  ██║╚════██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████║    ██╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚════██║   ██╔╝
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║         ██║   ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝         ╚═╝   ╚═╝{RS}
{DM} ─────────────────────────────────────────────────────────────────
  Automated Reconnaissance & Vulnerability Scanner  |  Author: Munia936
  Version 2.0  |  For Authorized Security Testing Only
 ─────────────────────────────────────────────────────────────────{RS}
""")

def section(title):
    bar = "─" * (55 - len(title))
    print(f"\n{C}┌─[ {B}{W}{title}{RS}{C} ]{bar}┐{RS}")

def end_section():
    print(f"{DM}{'─'*62}{RS}")

def ok(msg):    print(f"  {G}[✔]{RS} {msg}")
def warn(msg):  print(f"  {Y}[!]{RS} {msg}")
def info(msg):  print(f"  {C}[*]{RS} {msg}")
def err(msg):   print(f"  {R}[✘]{RS} {msg}")
def vuln(msg):  print(f"  {R}[VULN]{RS} {B}{msg}{RS}")
def found(msg): print(f"  {M}[+]{RS} {msg}")

def kv(key, val, color=None):
    col = color or W
    print(f"  {DM}│{RS}  {DM}{key:<28}{RS} {col}{val}{RS}")

def progress(label, current, total):
    pct = int((current / total) * 30)
    bar = "█" * pct + "░" * (30 - pct)
    sys.stdout.write(f"\r  {C}[{bar}]{RS} {label} {current}/{total}  ")
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")
