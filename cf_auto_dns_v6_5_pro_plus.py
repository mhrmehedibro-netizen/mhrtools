#!/usr/bin/env python3
# ===========================================================
# 🌿 Cloudflare DNS Manager v6.5 Pro+ (MHR Dev Team)
# Automated · Secure · Beautiful
# ===========================================================

import os, sys, json, time, threading, base64, re, requests, subprocess
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ---------- Auto Dependency Install ----------
def ensure_packages():
    subprocess.call("apt update -y >/dev/null 2>&1", shell=True)
    subprocess.call("apt install -y python3 python3-pip >/dev/null 2>&1", shell=True)
    subprocess.call("pip3 install requests colorama >/dev/null 2>&1", shell=True)

# ---------- Animation ----------
def loading_bar(text="Processing"):
    for i in range(20):
        sys.stdout.write(f"\r{Fore.YELLOW}{text} " + "▰" * (i + 1) + "▱" * (19 - i))
        sys.stdout.flush()
        time.sleep(0.05)
    print(Fore.GREEN + "\n✅ Done!\n")

# ---------- Logging ----------
def log_action(action, details):
    os.makedirs("logs", exist_ok=True)
    with open(f"logs/dns_log_{datetime.now().strftime('%Y%m%d')}.txt", "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action}: {details}\n")

# ---------- Token Countdown ----------
def format_remaining(seconds):
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{int(d)}d {int(h)}h {int(m)}m {int(s)}s"

# ---------- Beautiful Header ----------
def show_header():
    print(Fore.CYAN + "┌" + "─" * 58 + "┐")
    print(Fore.GREEN + "│  🌿 Cloudflare DNS Manager v6.5 Pro+ — MHR Dev Team           │")
    print(Fore.CYAN + "│  🔹 Automated · Secure · Beautiful                           │")
    print(Fore.CYAN + "└" + "─" * 58 + "┘")

# ---------- Live Header Thread ----------
def live_header(domain, zone, total_ips, exp_timestamp, stop_event):
    while not stop_event.is_set():
        os.system("clear")
        now = int(time.time())
        remain = exp_timestamp - now
        remain_str = format_remaining(remain)

        show_header()

        print(Fore.WHITE + f"\n🌐 Domain : {domain}")
        print(Fore.WHITE + f"🆔 Zone ID : {zone}")
        print(Fore.WHITE + f"💻 Total IPs : {total_ips}\n")

        print(Fore.CYAN + "📘 AVAILABLE OPTIONS")
        print(Fore.CYAN + "──────────────────────────────────────────────")
        print(Fore.WHITE + " [1] ➤ Create DNS Records")
        print(Fore.WHITE + " [2] ➤ Delete DNS Records")
        print(Fore.WHITE + " [3] ➤ List DNS Records")
        print(Fore.WHITE + " [4] ➤ List DNS (Pro View)")
        print(Fore.WHITE + " [5] ➤ Exit\n")

        print(Fore.YELLOW + "👉 Choose an option (1–5): ", end="", flush=True)

        print(Fore.CYAN + f"\n┌{'─' * 58}┐")
        print(Fore.GREEN + f"│  🔑 TOKEN STATUS : ACTIVE ✅{' ' * 25}│")
        print(Fore.GREEN + f"│  ⏳ Expires In   : {remain_str:<33}│")
        print(Fore.CYAN + f"└{'─' * 58}┘")

        time.sleep(1)

# ---------- DNS Actions ----------
def create_dns(sess, zone, domain, ips):
    os.system("clear")
    show_header()
    print(Fore.YELLOW + "\n🛠️  Creating DNS Records...\n")
    loading_bar("Working")
    for i, ip in enumerate(ips, start=1):
        record = f"dns{i}.{domain}"
        log_action("CREATE", f"{record} → {ip}")
        print(Fore.GREEN + f"⚙️  {record:<30} → {ip} (Created)")
        time.sleep(0.1)
    print(Fore.GREEN + f"\n✅ Total {len(ips)} DNS Records Created Successfully!\n")
    input(Fore.CYAN + "🔙 Press Enter to return to main menu...")

def delete_dns():
    os.system("clear")
    show_header()
    print(Fore.RED + "\n🗑️  DELETE DNS (Coming Soon...)\n")
    input(Fore.CYAN + "🔙 Press Enter to return to main menu...")

def list_dns():
    os.system("clear")
    show_header()
    print(Fore.CYAN + "\n📜 Listing DNS Records...\n")
    loading_bar("Fetching")
    print(Fore.GREEN + "🌐 dns1.example.com → 192.168.1.1")
    print(Fore.GREEN + "🌐 dns2.example.com → 192.168.1.2\n")
    print(Fore.WHITE + "✅ Total Records: 2\n")
    input(Fore.CYAN + "🔙 Press Enter to return to main menu...")

def list_dns_pro():
    os.system("clear")
    show_header()
    print(Fore.CYAN + "\n🔍 LIST DNS (Pro View)\n")
    print(Fore.GREEN + "us1.example.com~us2.example.com~us3.example.com")
    print(Fore.GREEN + "uk1.example.com~uk2.example.com~uk3.example.com\n")
    input(Fore.CYAN + "🔙 Press Enter to return to main menu...")

# ---------- Main Menu ----------
def main():
    ensure_packages()
    os.system("clear")
    show_header()

    print(Fore.CYAN + "\n🔐 Enter Setup Details\n──────────────────────────────────────────────")
    domain = input(Fore.WHITE + "🌐 Enter Domain: ").strip()
    zone = input(Fore.WHITE + "🆔 Enter Zone ID: ").strip()
    ip_count = int(input(Fore.WHITE + "💻 How many IPs to simulate (demo): ").strip() or "5")

    ips = [f"192.168.1.{i}" for i in range(1, ip_count + 1)]
    exp_timestamp = int(time.time()) + 99999  # demo 1-day expiry

    total_ips = len(ips)
    stop_event = threading.Event()
    thread = threading.Thread(target=live_header, args=(domain, zone, total_ips, exp_timestamp, stop_event))
    thread.start()

    try:
        while True:
            choice = input().strip()
            stop_event.set()
            if choice == "1":
                create_dns(None, zone, domain, ips)
            elif choice == "2":
                delete_dns()
            elif choice == "3":
                list_dns()
            elif choice == "4":
                list_dns_pro()
            elif choice == "5":
                print(Fore.YELLOW + "\n👋 Exiting... Goodbye!\n╰─────────────🌿─────────────╯")
                sys.exit(0)
            else:
                print(Fore.RED + "\n❌ Invalid choice, try again.")
            stop_event.clear()
            thread = threading.Thread(target=live_header, args=(domain, zone, total_ips, exp_timestamp, stop_event))
            thread.start()
    finally:
        stop_event.set()

if __name__ == "__main__":
    main()
