#!/usr/bin/env python3
# ===========================================================
# 🌿 MHR Access Key Generator v4.1 — Full Auto Installer Edition
# Auto-update · Auto-install · Clipboard Safe · Auto-Run DNS Script
# ===========================================================

import os, sys, time, secrets, subprocess
from datetime import datetime, timedelta

# ---------- Auto Dependency Setup ----------
def auto_setup():
    print("\n🛠️  Preparing system environment...\n")
    cmds = [
        "apt update -y && apt upgrade -y",
        "apt install -y python3 python3-pip curl nano wget unzip",
        "apt install -y xclip xsel wl-clipboard",
        "pip3 install colorama requests cryptography pyperclip --break-system-packages"
    ]
    for cmd in cmds:
        print(f"⚙️ Running: {cmd}")
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("✅ Environment ready!\n")

# Run setup only once
auto_setup()

# ---------- Import after installation ----------
from colorama import Fore, Style, init
init(autoreset=True)
try:
    import pyperclip
except ImportError:
    subprocess.run(["pip3", "install", "pyperclip", "--break-system-packages"])
    import pyperclip

# ---------- Helper Functions ----------
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

# ---------- Main ----------
def main():
    os.system("clear")
    print(Fore.CYAN + "┌" + "─"*64 + "┐")
    print(Fore.GREEN + "│  🌿 MHR Access Key Generator v4.1 — Full Auto Installer      │")
    print(Fore.CYAN + "│  🔹 Auto Setup · Clipboard Safe · Auto Run DNS Script        │")
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

    # Safe clipboard copy
    try:
        pyperclip.copy(full_key)
        clip_msg = Fore.GREEN + "📋 Copied to clipboard successfully!"
    except pyperclip.PyperclipException:
        clip_msg = Fore.YELLOW + "⚠️  Clipboard not available — skipping copy."

    # Display key
    print(Fore.CYAN + "\n──────────────────────────────────────────────────────────────")
    print(Fore.GREEN + "✅ Access Key Generated\n")
    print(Fore.WHITE + f"📅 Issued  : {issued:%Y-%m-%d %H:%M:%S UTC}")
    print(Fore.WHITE + f"⏳ Expires : {expiry:%Y-%m-%d %H:%M:%S UTC}")
    print(Fore.CYAN + "──────────────────────────────────────────────────────────────")
    print(Fore.GREEN + "🔐 Your Access Key:\n")
    print(Fore.WHITE + Style.BRIGHT + "╔" + "═"*56 + "╗")
    print(Fore.YELLOW + Style.BRIGHT + f"  {full_key}")
    print(Fore.WHITE + Style.BRIGHT + "╚" + "═"*56 + "╝")
    print(Fore.CYAN + "──────────────────────────────────────────────────────────────")
    print(clip_msg)
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
