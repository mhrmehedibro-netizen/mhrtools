#!/usr/bin/env python3
# ─────────────────────────────────────────────
#  Cloudflare DNS Manager v9.0 (Full Ultimate Edition)
#  Made by MHR 🌿
#  Developed & Maintained by MHR Dev Team
#  Secure • Automated • Smart
# ─────────────────────────────────────────────

# ⚙️ Main Script Starts Here ↓

import requests, json, os, time, getpass, random, string, re, sys
from datetime import datetime

CRED_FILE = "credentials.json"
DIV = "────────────────────────────────────────────"

def short_progress_bar():
    width = 10
    for i in range(width + 1):
        filled = "█" * i
        empty = "░" * (width - i)
        pct = int((i / width) * 100)
        sys.stdout.write(f"\r|{filled}{empty}| {pct:3d}%")
        sys.stdout.flush()
        time.sleep(0.07)
    print("")

def timed_input_list(prompt="Paste IPs (one per line). Press Enter twice to finish:"):
    print(prompt)
    lines = []
    while True:
        line = input().strip()
        if line == "":
            break
        lines.append(line)
    return lines

# ---------- LOGIN ----------
def save_credentials(token, zone_id, domain):
    with open(CRED_FILE, "w") as f:
        json.dump({"token": token, "zone_id": zone_id, "domain": domain}, f)
    print("✅ Credentials saved successfully.\n")

def load_credentials():
    if os.path.exists(CRED_FILE):
        with open(CRED_FILE, "r") as f:
            return json.load(f)
    return None

def delete_credentials():
    if os.path.exists(CRED_FILE):
        os.remove(CRED_FILE)
        print("✅ Logged out successfully. Credentials removed.\n")

def get_auth():
    creds = load_credentials()
    if creds:
        print(f"🔐 Auto login successful ({creds['domain']})\n")
        return creds["token"], creds["zone_id"], creds["domain"]

    print("🔑 Cloudflare Login Required:")
    token = getpass.getpass("Enter Cloudflare API Token: ").strip()
    zone_id = input("Enter Cloudflare Zone ID: ").strip()
    domain = input("Enter your Domain Name: ").strip()
    if input("Save these credentials for future use? (y/n): ").lower() == "y":
        save_credentials(token, zone_id, domain)
    return token, zone_id, domain

# ---------- UTILITIES ----------
def cf_headers(token): return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def cf_get(session, url, params=None): return session.get(url, params=params)
def cf_post(session, url, payload): return session.post(url, json=payload)
def cf_put(session, url, payload): return session.put(url, json=payload)
def cf_delete(session, url): return session.delete(url)

def list_dns(session, zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    data = session.get(url).json()
    return data.get("result", [])

def get_zone_status(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    if r.status_code == 200:
        status = r.json().get("result", {}).get("status", "")
        return 1 if status in ["suspended", "locked"] else 0
    return 0

def get_total_dns_count(session, zone_id):
    recs = list_dns(session, zone_id)
    return len(recs)

# ---------- CREATE DNS ----------
def create_dns_records(session, zone_id, domain):
    base = input("\nBase name (us/uk/ca/custom): ").strip().lower()
    ips = timed_input_list()
    if not ips: return
    start = time.perf_counter()
    for i, ip in enumerate(ips, start=1):
        sub = f"{base}{i}.{domain}"
        print(f"({i}/{len(ips)}) Creating {sub}")
        short_progress_bar()
        cf_post(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                {"type": "A", "name": sub, "content": ip, "ttl": 1, "proxied": False})
        print(f"✅ {sub} → {ip}\n")
    print(f"Total Created: {len(ips)} | Time: {time.perf_counter()-start:.2f}s\n")

def create_dns_random(session, zone_id, domain):
    ips = timed_input_list()
    if not ips: return
    start = time.perf_counter()
    for i, ip in enumerate(ips, start=1):
        sub = f"{''.join(random.choices(string.ascii_lowercase+string.digits, k=4))}.{domain}"
        print(f"({i}/{len(ips)}) Creating {sub}")
        short_progress_bar()
        cf_post(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                {"type": "A", "name": sub, "content": ip, "ttl": 1, "proxied": False})
        print(f"✅ {sub} → {ip}\n")
    print(f"Total Created: {len(ips)} | Time: {time.perf_counter()-start:.2f}s\n")

# ---------- DELETE ----------
def delete_dns(session, zone_id):
    print("\n1) Delete by Name\n2) Delete All\n3) Back")
    c = input("Choose: ").strip()
    if c == "1":
        name = input("DNS name to delete: ").strip()
        data = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", {"name": name}).json()
        if not data.get("result"): return print("Not found.")
        rid = data["result"][0]["id"]
        cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
        print(f"🗑️ Deleted {name}\n")
    elif c == "2":
        if input("⚠️ Delete ALL DNS? (y/n): ").lower() == "y":
            recs = list_dns(session, zone_id)
            for i, rec in enumerate(recs, start=1):
                cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec['id']}")
                print(f"({i}/{len(recs)}) Deleted {rec['name']}")
            print("✅ All deleted.\n")

# ---------- DNS LIST ----------
def list_normal(session, zone_id):
    recs = list_dns(session, zone_id)
    for r in recs:
        print(f"{r['name']} {r['content']}")
    open("dns_list_normal.txt", "w").write("\n".join([f"{r['name']} {r['content']}" for r in recs]))
    print("\nSaved to dns_list_normal.txt\n")

def list_pro(session, zone_id):
    recs = list_dns(session, zone_id)
    groups = {}
    for r in recs:
        pre = re.match(r"^([a-zA-Z]+)", r["name"].split(".")[0])
        key = pre.group(1) if pre else "other"
        groups.setdefault(key, []).append(r["name"])
    with open("dns_list_pro.txt", "w") as f:
        for k, v in groups.items():
            print(k.upper(), "\n" + "~".join(v) + "\n")
            f.write(k.upper() + "\n" + "~".join(v) + "\n\n")
    print("Saved to dns_list_pro.txt\n")

# ---------- SSL & NS ----------
def ssl_manager(session, zone_id):
    while True:
        print("\n1. Show SSL\n2. Set Flexible\n3. Set Full\n4. Set Strict\n5. Back")
        s = input("Choose: ")
        if s == "1":
            print(session.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl").json())
        elif s in ["2", "3", "4"]:
            mode = {"2": "flexible", "3": "full", "4": "strict"}[s]
            cf_put(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl", {"value": mode})
            print(f"SSL mode set → {mode}\n")
        elif s == "5": break

def nameserver_manager(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    ns = r.json().get("result", {}).get("name_servers", [])
    print("\nNameservers:")
    for n in ns: print(" -", n)
    print("")

# ---------- TOOLS ----------
def domain_add(session):
    d = input("New domain to add: ").strip()
    cf_post(session, "https://api.cloudflare.com/client/v4/zones", {"name": d, "jump_start": True})
    print(f"✅ Added {d}\n")

def domain_remove(session, zone_id, domain):
    recs = list_dns(session, zone_id)
    for r in recs:
        cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{r['id']}")
    print(f"✅ Cleared all DNS for {domain}\n")

def abuse_check(session, zone_id, domain):
    flag = get_zone_status(session, zone_id)
    print(f"{domain} → {'⚠️ Suspended' if flag else '✅ Clean'}\n")

def tools(session, zone_id, domain):
    while True:
        print("\n1. Domain Add\n2. Domain Remove\n3. Abuse Check\n4. Back")
        c = input("Choose: ")
        if c == "1": domain_add(session)
        elif c == "2": domain_remove(session, zone_id, domain)
        elif c == "3": abuse_check(session, zone_id, domain)
        elif c == "4": break

# ---------- MAIN ----------
def main():
    token, zone_id, domain = get_auth()
    s = requests.Session()
    s.headers.update(cf_headers(token))
    while True:
        abuse = get_zone_status(s, zone_id)
        total = get_total_dns_count(s, zone_id)
        print(f"\n🌿 Cloudflare DNS Manager v9.0  |  Made by MHR\n{DIV}")
        print(f"Domain: {domain}\nTotal DNS: {total}\nAbuse: {abuse}\n{DIV}")
        print("1. Create DNS\n2. Create DNS (Random)\n3. Delete DNS\n4. DNS List (Normal)\n5. DNS List (Pro)")
        print("6. Name Server Manager\n7. SSL/TLS Mode Manager\n8. Tools\n9. Logout\n10. Exit\n" + DIV)
        ch = input("Choose (1-10): ").strip()
        if ch == "1": create_dns_records(s, zone_id, domain)
        elif ch == "2": create_dns_random(s, zone_id, domain)
        elif ch == "3": delete_dns(s, zone_id)
        elif ch == "4": list_normal(s, zone_id)
        elif ch == "5": list_pro(s, zone_id)
        elif ch == "6": nameserver_manager(s, zone_id)
        elif ch == "7": ssl_manager(s, zone_id)
        elif ch == "8": tools(s, zone_id, domain)
        elif ch == "9": delete_credentials(); break
        elif ch == "10": print("👋 Goodbye!"); break
        else: print("Invalid choice.\n")

if __name__ == "__main__":
    main()
