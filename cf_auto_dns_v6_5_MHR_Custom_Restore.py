#!/usr/bin/env python3
# cf_auto_dns_v6_5_MHR_Custom_Restore.py
# 🌿 Cloudflare DNS Manager v6.5 Pro — MHR Dev Team (Custom Restore)
# Live Cloudflare integration, no token system, custom UI & functions restored.

import os, sys, time, subprocess
from datetime import datetime

# ensure dependencies
def ensure_packages():
    try:
        import colorama, requests  # noqa: F401
    except Exception:
        print("📦 Installing required Python packages (colorama, requests)...")
        subprocess.run([sys.executable, "-m", "pip", "install", "colorama", "requests"], stdout=subprocess.DEVNULL)
    # import after install
    global Fore, Style, init, requests
    from colorama import Fore, Style, init
    import requests
    init(autoreset=True)

ensure_packages()
from colorama import Fore, Style, init
import requests

# -------------------------
# UI / layout (MHR style)
# -------------------------
def show_header():
    print(Fore.CYAN + "┌" + "─"*62 + "┐")
    print(Fore.GREEN + "│  🌿 Cloudflare DNS Manager v6.5 Pro — MHR Dev Team           │")
    print(Fore.CYAN + "└" + "─"*62 + "┘\n")

def show_domain_info(domain, zone_id, total_ips):
    print(Fore.WHITE + f"🌐 Domain : {domain}")
    print(Fore.WHITE + f"🆔 Zone ID : {zone_id}")
    print(Fore.WHITE + f"💻 Total IPs : {total_ips}\n")

def show_menu():
    print(Fore.CYAN + "📘 AVAILABLE OPTIONS")
    print(Fore.WHITE + "──────────────────────────────────────────────")
    print(" [1] ➤ Create DNS Records")
    print(" [2] ➤ Delete DNS Records")
    print(" [3] ➤ List DNS Records")
    print(" [4] ➤ List DNS (Pro View)")
    print(" [5] ➤ Exit\n")

def show_token_box_note():
    # no token system — but show stable status box to match design
    print(Fore.CYAN + "┌" + "─"*62 + "┐")
    print(Fore.GREEN + "│  🔐 MODE : LIVE CLOUDFLARE (No Token)                       │")
    print(Fore.YELLOW + "│  ℹ️  Enter Cloudflare API Token & Zone ID when prompted     │")
    print(Fore.CYAN + "└" + "─"*62 + "┘\n")

# -------------------------
# Cloudflare API helpers
# -------------------------
CF_API = "https://api.cloudflare.com/client/v4"

def cf_headers(api_token):
    return {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

def api_create_dns(zone_id, name, ip, api_token):
    payload = {"type":"A","name":name,"content":ip,"ttl":120,"proxied":False}
    try:
        r = requests.post(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(api_token), json=payload, timeout=15)
        return r.status_code == 200 or r.status_code == 201, r.text
    except Exception as e:
        return False, str(e)

def api_list_dns(zone_id, api_token):
    try:
        r = requests.get(f"{CF_API}/zones/{zone_id}/dns_records?per_page=100", headers=cf_headers(api_token), timeout=15)
        if r.status_code == 200:
            return [d["name"] for d in r.json().get("result", [])]
        else:
            print(Fore.RED + f"⚠️ Failed to fetch DNS records ({r.status_code})")
            return []
    except Exception as e:
        print(Fore.RED + f"⚠️ Error fetching DNS records: {e}")
        return []

def api_get_record_id(zone_id, fqdn, api_token):
    try:
        params = {"name": fqdn}
        r = requests.get(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(api_token), params=params, timeout=15)
        if r.status_code == 200:
            results = r.json().get("result", [])
            if results:
                return results[0]["id"]
    except Exception as e:
        pass
    return None

def api_delete_record(zone_id, record_id, api_token):
    try:
        r = requests.delete(f"{CF_API}/zones/{zone_id}/dns_records/{record_id}", headers=cf_headers(api_token), timeout=15)
        return r.status_code == 200
    except Exception as e:
        return False

# -------------------------
# Custom functions (your style)
# -------------------------
def create_dns_flow(domain, zone_id, api_token):
    prefix = input("Enter prefix (e.g. us): ").strip() or "dns"
    ips_text = input("Paste IPs (comma separated): ").strip()
    if not ips_text:
        print(Fore.YELLOW + "No IPs provided. Cancelled.")
        time.sleep(1.2)
        return
    ips = [ip.strip() for ip in ips_text.split(",") if ip.strip()]
    total = len(ips)
    print(Fore.CYAN + f"\nCreating {total} DNS Records for {domain}...\n")
    created = 0
    for i, ip in enumerate(ips, start=1):
        sub = f"{prefix}{i}.{domain}"
        # animated creation line
        print(Fore.GREEN + f"Creating {sub} → {ip} ...", end="", flush=True)
        ok, resp = api_create_dns(zone_id, sub, ip, api_token)
        time.sleep(0.3)  # your small delay
        if ok:
            print(" ✅")
            created += 1
        else:
            print(Fore.RED + f" ❌ (failed) ")
            # you might want to print resp for debug
            # print(Fore.YELLOW + str(resp))
    print(Fore.CYAN + f"\n✅ Done — Created {created}/{total} records.\n")
    input(Fore.YELLOW + "Press Enter to return to menu...")

def delete_dns_flow(domain, zone_id, api_token):
    # single confirmation (you asked for one confirm)
    fqdn = input("Enter full DNS name to delete (e.g. us1.example.com): ").strip()
    if not fqdn:
        print(Fore.YELLOW + "No input. Cancelled.")
        time.sleep(1)
        return
    confirm = input(Fore.YELLOW + f"Are you sure you want to delete {fqdn}? (y/n): ").strip().lower()
    if confirm != 'y':
        print(Fore.CYAN + "Cancelled.")
        time.sleep(0.8)
        return
    print(Fore.RED + f"Deleting {fqdn} ...", end="", flush=True)
    rec_id = api_get_record_id(zone_id, fqdn, api_token)
    time.sleep(0.35)
    if rec_id:
        ok = api_delete_record(zone_id, rec_id, api_token)
        if ok:
            print(" ❌ Deleted!")
        else:
            print(" ❌ Failed to delete.")
    else:
        print(Fore.YELLOW + " ❗ Record not found.")
    input(Fore.YELLOW + "Press Enter to return to menu...")

def list_dns_flow(zone_id, api_token):
    os.system("clear")
    print(Fore.CYAN + "──────────────────────────────")
    print(Fore.GREEN + "📜 DNS Records List")
    print(Fore.CYAN + "──────────────────────────────\n")
    records = api_list_dns(zone_id, api_token)
    if not records:
        print(Fore.YELLOW + "⚠️ No DNS records found.\n")
    else:
        for idx, rec in enumerate(records, start=1):
            print(Fore.WHITE + f"{idx:02d}. {rec}")
    input(Fore.YELLOW + "\nPress Enter to return...")

def pro_dns_view_flow(zone_id, api_token):
    os.system("clear")
    print(Fore.CYAN + "──────────────────────────────")
    print(Fore.GREEN + "💠 Pro DNS View")
    print(Fore.CYAN + "──────────────────────────────\n")
    records = api_list_dns(zone_id, api_token)
    if not records:
        print(Fore.YELLOW + "⚠️ No DNS records available.\n")
    else:
        compact = "~".join([r.split(".")[0] for r in records])
        print(Fore.GREEN + compact + "\n")
    input(Fore.YELLOW + "Press Enter to return...")

# -------------------------
# Main program
# -------------------------
def main():
    os.system("clear")
    show_header()
    # ask for Cloudflare details
    api_token = input(Fore.CYAN + "🔐 Enter Cloudflare API Token: ").strip()
    zone_id = input(Fore.CYAN + "🆔 Enter Cloudflare Zone ID: ").strip()
    domain = input(Fore.CYAN + "🌐 Enter Domain Name: ").strip() or "example.com"
    total_ips = 20

    while True:
        os.system("clear")
        show_header()
        show_domain_info(domain, zone_id, total_ips)
        show_menu()
        show_token_box_note()
        choice = input(Fore.YELLOW + "👉 Choose an option (1–5): ").strip()
        if choice == "1":
            create_dns_flow(domain, zone_id, api_token)
        elif choice == "2":
            delete_dns_flow(domain, zone_id, api_token)
        elif choice == "3":
            list_dns_flow(zone_id, api_token)
        elif choice == "4":
            pro_dns_view_flow(zone_id, api_token)
        elif choice == "5":
            print(Fore.YELLOW + "\n👋 Exiting... Goodbye!")
            break
        else:
            print(Fore.RED + "Invalid option.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(0)
