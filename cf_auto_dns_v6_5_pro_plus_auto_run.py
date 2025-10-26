#!/usr/bin/env python3
# ===========================================================
# 🌿 Cloudflare DNS Manager v6.5 Pro+ — Auto Run Edition
# Auto-install · Token Argument Ready · One-Step Start
# ===========================================================

import os, sys, subprocess, time
from datetime import datetime

# ── Auto-install dependencies ───────────────────────────────
def ensure_deps():
    try:
        import colorama
    except ImportError:
        print("📦 Installing required module: colorama ...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "colorama"])
    os.system("clear")

ensure_deps()
from colorama import Fore, Style, init
init(autoreset=True)

# ── Token Validation ───────────────────────────────
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

# ── Dashboard ───────────────────────────────
def show_header():
    print(Fore.CYAN + "┌" + "─" * 58 + "┐")
    print(Fore.GREEN + "│  🌿 Cloudflare DNS Manager v6.5 Pro+ — MHR Dev Team          │")
    print(Fore.CYAN + "│  🔹 Auto-Run · Token Auth · Beautiful UI                     │")
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

if __name__ == "__main__":
    os.system("clear")
    # Check if token was passed as argument
    if len(sys.argv) > 1:
        ACCESS_KEY = sys.argv[1]
    else:
        ACCESS_KEY = input(Fore.YELLOW + "🔑 Paste Access Key: ").strip()

    exp_ts = validate_access_key(ACCESS_KEY)
    main_menu(exp_ts, ACCESS_KEY)
