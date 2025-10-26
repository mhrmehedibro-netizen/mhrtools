#!/usr/bin/env python3
# ===========================================================
# 🌿 Cloudflare DNS Manager v6.6 Ultimate Auto-Run Edition
# Full auto dependency setup + token access + dashboard
# Compatible: Debian 10-12, Ubuntu 20-24+
# ===========================================================

import os, sys, subprocess, time
from datetime import datetime

# ─────────────────────────── Auto Install Section ───────────────────────────
def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip()

def ensure_system_ready():
    print("🔧 Checking system dependencies...\n")
    os.system("sleep 1")
    
    # Step 1: Update + Upgrade
    print("📦 Updating system packages...")
    os.system("sudo apt update -y && sudo apt upgrade -y")

    # Step 2: Install essentials
    essentials = "python3 python3-pip curl nano"
    print(f"📥 Installing essentials: {essentials}")
    os.system(f"sudo apt install -y {essentials}")

    # Step 3: Install Python modules
    modules = ["colorama", "requests", "cryptography", "pyperclip"]
    for m in modules:
        print(f"📚 Installing Python module: {m}")
        os.system(f"pip3 install {m} --break-system-packages -q")

    os.system("clear")
    print("✅ Environment ready!\n")

# ─────────────────────────── Imports ───────────────────────────
def safe_imports():
    try:
        from colorama import Fore, Style, init
    except ImportError:
        ensure_system_ready()
        from colorama import Fore, Style, init
    return Fore, Style, init

Fore, Style, init = safe_imports()
init(autoreset=True)

# ─────────────────────────── Token Validation ───────────────────────────
def base36_decode(s: str) -> int:
    return int(s, 36)

def validate_access_key(token: str):
    try:
        if "." not in token:
            print(Fore.RED + "❌ Invalid token format.")
            sys.exit(1)
        _, exp_b36 = token.rsplit(".", 1)
        exp_ts = base36_decode(exp_b36)
        if time.time() > exp_ts:
            print(Fore.RED + "⏳ Token expired. Please generate a new key.")
            sys.exit(1)
        return exp_ts
    except Exception as e:
        print(Fore.RED + f"❌ Token validation error: {e}")
        sys.exit(1)

# ─────────────────────────── UI / Dashboard ───────────────────────────
def show_header():
    print(Fore.CYAN + "┌" + "─" * 58 + "┐")
    print(Fore.GREEN + "│  🌿 Cloudflare DNS Manager v6.6 Ultimate — MHR Dev Team      │")
    print(Fore.CYAN + "│  🔹 Auto Install · Token Auth · Premium Dashboard             │")
    print(Fore.CYAN + "└" + "─" * 58 + "┘\n")

def dashboard(domain, zone_id, total_ips, exp_ts, access_key):
    os.system("clear")
    show_header()
    remaining = max(0, int(exp_ts - time.time()))
    d, r = divmod(remaining, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    expire_text = f"{d}d {h}h {m}m {s}s"

    print(Fore.CYAN + "┌" + "─" * 58 + "┐")
    print(Fore.CYAN + "│ 📂 DOMAIN INFO                                               │")
    print(Fore.CYAN + "│" + "─" * 58 + "│")
    print(Fore.WHITE + f"│ 🌐 Domain     : example.com                                  │")
    print(Fore.WHITE + f"│ 🆔 Zone ID    : 9234x981923x8123                             │")
    print(Fore.WHITE + f"│ 💻 Total IPs  : 20                                           │")
    print(Fore.CYAN + "└" + "─" * 58 + "┘\n")

    print(Fore.CYAN + "┌" + "─" * 58 + "┐")
    print(Fore.CYAN + "│ ⚙️  DNS ACTIONS (AVAILABLE OPTIONS)                         │")
    print(Fore.CYAN + "│" + "─" * 58 + "│")
    print(Fore.WHITE + "│ [1] ➤ Create DNS Records                                    │")
    print(Fore.WHITE + "│ [2] ➤ Delete DNS Records                                    │")
    print(Fore.WHITE + "│ [3] ➤ List DNS Records                                      │")
    print(Fore.WHITE + "│ [4] ➤ List DNS (Pro View)                                   │")
    print(Fore.WHITE + "│ [5] ➤ Exit                                                  │")
    print(Fore.CYAN + "└" + "─" * 58 + "┘\n")

    choice = input(Fore.YELLOW + "👉 Choose an option (1–5): ").strip()
    print()

    print(Fore.CYAN + "┌" + "─" * 58 + "┐")
    print(Fore.GREEN + "│  🔑 TOKEN STATUS : ACTIVE ✅                                 │")
    print(Fore.WHITE + f"│  🧩 Access Key   : {access_key[:50]:<44}│")
    print(Fore.YELLOW + f"│  ⏳ Expires In   : {expire_text:<43}│")
    print(Fore.CYAN + "└" + "─" * 58 + "┘\n")

    return choice

# ─────────────────────────── DNS Manager (Demo actions) ───────────────────────────
def main_menu(exp_ts, access_key):
    while True:
        choice = dashboard("example.com", "9234x981923x8123", 20, exp_ts, access_key)
        if choice == "1":
            print(Fore.GREEN + "\n🛠️  Creating DNS... (demo)")
            time.sleep(2)
        elif choice == "2":
            print(Fore.RED + "\n🗑️  Deleting DNS... (demo)")
            time.sleep(2)
        elif choice == "3":
            print(Fore.CYAN + "\n📜 Listing DNS... (demo)")
            time.sleep(2)
        elif choice == "4":
            print(Fore.YELLOW + "\n🔍 Listing DNS (Pro View)... (demo)")
            time.sleep(2)
        elif choice == "5":
            print(Fore.YELLOW + "\n👋 Exiting... Goodbye!")
            sys.exit(0)
        input(Fore.CYAN + "\n🔙 Press Enter to return to dashboard...")

# ─────────────────────────── Entry ───────────────────────────
if __name__ == "__main__":
    os.system("clear")
    print(Fore.GREEN + "🌿 Cloudflare DNS Manager v6.6 (Auto Installer Enabled)\n")
    print(Fore.YELLOW + "🔧 Initializing environment...\n")
    ensure_system_ready()

    if len(sys.argv) > 1:
        ACCESS_KEY = sys.argv[1]
    else:
        ACCESS_KEY = input(Fore.YELLOW + "🔑 Paste Access Key: ").strip()

    exp_ts = validate_access_key(ACCESS_KEY)
    main_menu(exp_ts, ACCESS_KEY)
