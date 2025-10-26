#!/usr/bin/env python3
# token_gen_ultra_v4_1_full_auto.py
# 🌿 MHR Access Key Generator v4.1 — Full Auto Installer Edition
# Auto-update · Auto-install · Clipboard Safe · Auto-Run DNS Script

import os, sys, time, secrets, subprocess
from datetime import datetime, timedelta

# -------------------- Auto setup (apt + pip + clipboard tools) --------------------
def run(cmd):
    return subprocess.run(cmd, shell=True)

def auto_setup():
    print("\n🛠️ Preparing system environment (this may take a while)...\n")
    # update + upgrade
    run("sudo apt update -y && sudo apt upgrade -y")
    # essentials
    run("sudo apt install -y python3 python3-pip curl wget nano unzip")
    # clipboard support (tries to install both X11 & Wayland helpers)
    run("sudo apt install -y xclip xsel wl-clipboard || true")
    # pip modules (use --break-system-packages for newer Debian/Ubuntu when needed)
    run("pip3 install colorama requests cryptography pyperclip --break-system-packages -q || pip3 install colorama requests cryptography pyperclip -q")
    print("✅ Environment ready!\n")

# run auto setup once at script start
auto_setup()

# -------------------- imports (after installing) --------------------
try:
    from colorama import Fore, Style, init
    import pyperclip
except Exception as e:
    # try to (re)install if import fails
    run("pip3 install colorama pyperclip --break-system-packages -q || pip3 install colorama pyperclip -q")
    from colorama import Fore, Style, init
    import pyperclip

init(autoreset=True)

# -------------------- helpers --------------------
def base36_encode(num: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if num == 0: return "0"
    s = ""
    while num:
        num, rem = divmod(num, 36)
        s = digits[rem] + s
    return s

def grouped_token(core: str, group=4, sep="-"):
    groups = [core[i:i+group] for i in range(0, len(core), group)]
    return sep.join(groups)

def generate_core(length=28):
    tok = secrets.token_urlsafe(length*2)
    tok = "".join(ch for ch in tok if ch.isalnum())
    return tok[:length]

def animated_bar(text="Generating", steps=25, delay=0.03):
    for i in range(steps):
        bar = "▰"*(i+1) + "▱"*(steps-i-1)
        pct = int((i+1)/steps*100)
        sys.stdout.write(f"\r{Fore.YELLOW}{text} {bar} {pct}%")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def save_to_file(full_key, issued_at, expiry_at):
    fname = f"access_key_{issued_at.strftime('%Y%m%d_%H%M%S')}.txt"
    with open(fname, "w") as f:
        f.write("🌿 MHR Access Key\n")
        f.write(f"Issued At : {issued_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"Expires   : {expiry_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write(full_key + "\n")
    return fname

def beep():
    try:
        print("\a", end="", flush=True)
    except:
        pass

# -------------------- main --------------------
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
    hours = {"1":1, "2":24, "3":24*7, "4":24*30}.get(ch, 24)

    animated_bar("🔐 Creating key", steps=28, delay=0.03)

    issued = datetime.utcnow()
    expiry = issued + timedelta(hours=int(hours))
    exp_b36 = base36_encode(int(expiry.timestamp()))
    core = generate_core(28)
    full_key = f"{grouped_token(core)}.{exp_b36}"

    # Safe clipboard copy
    copied = False
    try:
        pyperclip.copy(full_key)
        copied = True
        clip_msg = Fore.GREEN + "📋 Copied to clipboard successfully!"
    except Exception:
        clip_msg = Fore.YELLOW + "⚠️ Clipboard not available — skipping copy."

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

    if input(Fore.YELLOW + "▶ Save key to file? [Y/n]: ").lower() in ("", "y"):
        fname = save_to_file(full_key, issued, expiry)
        print(Fore.GREEN + f"💾 Saved to: {fname}")

    if input(Fore.YELLOW + "▶ Run Cloudflare DNS Manager now? [Y/n]: ").lower() in ("", "y"):
        # call main script with token as arg
        run(f'python3 cf_auto_dns_v6_6_ultimate_auto_run.py "{full_key}"')
    else:
        print(Fore.CYAN + "\n✅ You can run manually with:\n" +
              f'python3 cf_auto_dns_v6_6_ultimate_auto_run.py "{full_key}"')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
