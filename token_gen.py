#!/usr/bin/env python3
# ===========================================================
# 🌿 MHR Access Key Generator v4.1 Auto-Run Edition
# Animated · Styled · Auto-save · Clipboard · Auto-Run DNS Script
# ===========================================================

import os, sys, time, secrets, subprocess
from datetime import datetime, timedelta

# ---------- Auto-install packages ----------
def ensure_package(pkg_name):
    try:
        __import__(pkg_name.split("[")[0])
    except ImportError:
        print(f"📦 Installing module: {pkg_name} ...")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg_name, "-q"])

for pkg in ["colorama", "pyperclip"]:
    ensure_package(pkg)
from colorama import Fore, Style, init
import pyperclip
init(autoreset=True)

# ---------- helpers ----------
def base36_encode(num):
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if num == 0: return "0"
    s = ""
    while num:
        num, rem = divmod(num, 36)
        s = digits[rem] + s
    return s

def grouped_token(core, group=4, sep="-"):
    return sep.join([core[i:i+group] for i in range(0, len(core), group)])

def generate_core(length=28):
    tok = secrets.token_urlsafe(length*2)
    tok = "".join(ch for ch in tok if ch.isalnum())
    return tok[:length]

def animated_bar(txt="Generating", steps=25, delay=0.03):
    for i in range(steps):
        bar = "▰"*(i+1) + "▱"*(steps-i-1)
        sys.stdout.write(f"\r{Fore.YELLOW}{txt} {bar} {int((i+1)/steps*100)}%")
        sys.stdout.flush()
        time.sleep(delay)
    print()

# ---------- main ----------
def main():
    os.system("clear")
    print(Fore.CYAN + "┌" + "─"*64 + "┐")
    print(Fore.GREEN + "│  🌿 MHR Access Key Generator v4.1 — Auto-Run Edition         │")
    print(Fore.CYAN + "│  🔹 Animated · Clipboard · Auto-Run DNS Script                │")
    print(Fore.CYAN + "└" + "─"*64 + "┘\n")

    print("Select validity:")
    print(" [1] 1 Hour")
    print(" [2] 1 Day (default)")
    print(" [3] 7 Days")
    print(" [4] 30 Days")
    ch = input(Fore.YELLOW + "Select (1-4): ").strip() or "2"
    hours = {"1":1, "2":24, "3":24*7, "4":24*30}.get(ch,"24")

    animated_bar("🔐 Creating key")

    issued = datetime.utcnow()
    expiry = issued + timedelta(hours=int(hours))
    exp_b36 = base36_encode(int(expiry.timestamp()))
    core = generate_core(28)
    full_key = f"{grouped_token(core)}.{exp_b36}"
    pyperclip.copy(full_key)

    print(Fore.CYAN + "\n──────────────────────────────────────────────────────────────")
    print(Fore.GREEN + "✅ Access Key Generated\n")
    print(Fore.WHITE + f"📅 Issued  : {issued:%Y-%m-%d %H:%M:%S UTC}")
    print(Fore.WHITE + f"⏳ Expires : {expiry:%Y-%m-%d %H:%M:%S UTC}")
    print(Fore.CYAN + "──────────────────────────────────────────────────────────────")
    print(Fore.GREEN + "🔐 Your Access Key:\n")
    print(Fore.WHITE + Style.BRIGHT + "╔" + "═"*56 + "╗")
    print(Fore.YELLOW + Style.BRIGHT + f"  {full_key}")
    print(Fore.WHITE + Style.BRIGHT + "╚" + "═"*56 + "╝")
    print(Fore.GREEN + "\n📋 Copied to clipboard!")
    print(Fore.CYAN + "──────────────────────────────────────────────────────────────")

    if input(Fore.YELLOW + "▶ Run Cloudflare DNS Manager now? [Y/n]: ").lower() in ("", "y"):
        os.system(f'python3 cf_auto_dns_v6_6_ultimate_auto_run.py "{full_key}"')
    else:
        print(Fore.CYAN + "\n✅ You can run manually with:\n"
              f"python3 cf_auto_dns_v6_6_ultimate_auto_run.py \"{full_key}\"")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
