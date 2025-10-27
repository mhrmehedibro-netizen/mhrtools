#!/usr/bin/env python3
# ==============================================================
# 🌿 Cloudflare DNS Manager v6.5 Pro — MHR Dev Team (Live Build)
# Real Cloudflare API Integration | Premium Dashboard | Stable
# ==============================================================

import os, sys, time, requests
from colorama import Fore, Style, init
init(autoreset=True)

# -------------------- UI Layout --------------------
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

# -------------------- Cloudflare API --------------------
CF_API = "https://api.cloudflare.com/client/v4"

def cf_headers(api_token):
    return {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

def create_dns(zone_id, name, ip, api_token):
    payload = {"type": "A", "name": name, "content": ip, "ttl": 120, "proxied": False}
    r = requests.post(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(api_token), json=payload)
    return r.status_code == 200

def list_dns(zone_id, api_token):
    r = requests.get(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(api_token))
    if r.status_code == 200:
        data = r.json().get("result", [])
        return [d["name"] for d in data]
    else:
        print(Fore.RED + f"⚠️ Failed to fetch DNS records ({r.status_code})")
        return []

def get_record_id(zone_id, fqdn, api_token):
    r = requests.get(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(api_token))
    if r.status_code == 200:
        for d in r.json()["result"]:
            if d["name"] == fqdn:
                return d["id"]
    return None

def delete_dns(zone_id, record_id, api_token):
    r = requests.delete(f"{CF_API}/zones/{zone_id}/dns_records/{record_id}", headers=cf_headers(api_token))
    return r.status_code == 200

# -------------------- Functional Options --------------------
def option_create_dns(domain, zone_id, api_token):
    prefix = input("Enter prefix (e.g. us): ").strip() or "dns"
    ips = input("Paste IPs (comma separated): ").strip().split(",")
    for i, ip in enumerate(ips, start=1):
        subdomain = f"{prefix}{i}.{domain}"
        print(Fore.GREEN + f"Creating {subdomain} → {ip.strip()} ...", end="")
        if create_dns(zone_id, subdomain, ip.strip(), api_token):
            print(" ✅")
        else:
            print(" ❌")
        time.sleep(0.2)
    print(Fore.CYAN + f"\n✨ Created {len(ips)} DNS records successfully!\n")
    input("Press Enter to return...")

def option_delete_dns(domain, zone_id, api_token):
    fqdn = input("Enter full DNS name to delete (e.g. us1.example.com): ").strip()
    rec_id = get_record_id(zone_id, fqdn, api_token)
    if not rec_id:
        print(Fore.YELLOW + "⚠️ Record not found.")
    else:
        if delete_dns(zone_id, rec_id, api_token):
            print(Fore.RED + f"Deleted {fqdn} ❌")
        else:
            print(Fore.RED + "❌ Failed to delete record.")
    input("Press Enter to return...")

def option_list_dns(zone_id, api_token):
    dns_list = list_dns(zone_id, api_token)
    if dns_list:
        print(Fore.CYAN + "\n📄 DNS Records:")
        for d in dns_list:
            print(" -", d)
    else:
        print(Fore.YELLOW + "No DNS records found.")
    input("\nPress Enter to return...")

def option_list_pro(zone_id, api_token):
    dns_list = list_dns(zone_id, api_token)
    if dns_list:
        compact = "~".join([x.split(".")[0] for x in dns_list])
        print(Fore.GREEN + "\nPro DNS View:\n" + compact)
    else:
        print(Fore.YELLOW + "No DNS records found.")
    input("\nPress Enter to return...")

# -------------------- Main Program --------------------
def main():
    os.system("clear")
    show_header()
    api_token = input(Fore.CYAN + "🔐 Enter Cloudflare API Token: ").strip()
    zone_id = input(Fore.CYAN + "🆔 Enter Cloudflare Zone ID: ").strip()
    domain = input(Fore.CYAN + "🌐 Enter Domain Name: ").strip() or "example.com"
    total_ips = 20

    while True:
        os.system("clear")
        show_header()
        show_domain_info(domain, zone_id, total_ips)
        show_menu()
        choice = input(Fore.YELLOW + "👉 Choose an option (1–5): ").strip()

        if choice == "1":
            option_create_dns(domain, zone_id, api_token)
        elif choice == "2":
            option_delete_dns(domain, zone_id, api_token)
        elif choice == "3":
            option_list_dns(zone_id, api_token)
        elif choice == "4":
            option_list_pro(zone_id, api_token)
        elif choice == "5":
            print(Fore.YELLOW + "\n👋 Exiting... Goodbye!")
            break
        else:
            print(Fore.RED + "❌ Invalid option.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(0)
