#!/usr/bin/env python3
# ─────────────────────────────────────────────
#  Cloudflare DNS Manager v9.4 (MHR Full Visual Edition)
#  Made by MHR 🌿
#  Developed & Maintained by MHR Dev Team
#  Visual Flow • Progress Bars • Flagged Pro View
# ─────────────────────────────────────────────

import requests, json, os, time, getpass, random, string, re, sys, itertools, threading
from datetime import datetime

CRED_FILE = "credentials.json"

# divider
DIV = "────────────────────────────────────────────"

# map prefix -> flag for Pro View
FLAG_MAP = {
    "us": "🇺🇸",
    "uk": "🇬🇧",
    "ca": "🇨🇦",
    "de": "🇩🇪",
    "fr": "🇫🇷",
    "jp": "🇯🇵",
    "in": "🇮🇳",
}

# -----------------------
# ANIMATION HELPERS
# -----------------------

def spinner_start(text="Processing"):
    """
    start spinner in background, return stop() function
    """
    done = {"stop": False}

    def run():
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if done["stop"]:
                break
            sys.stdout.write(f"\r{text} {c}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r")
        sys.stdout.flush()

    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

    def stop():
        done["stop"] = True
        # tiny sleep so spinner can clear
        time.sleep(0.15)

    return stop

def progress_bar(current, total, prefix=""):
    """
    draw a short progress bar like:
    ⚙️ Creating (3/10) |██████░░░░| 60%
    """
    width = 12
    ratio = (current / total) if total else 1
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(ratio * 100)
    sys.stdout.write(f"\r{prefix} ({current}/{total}) |{bar}| {pct}%")
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")

# -----------------------
# AUTH / CREDENTIALS
# -----------------------

def save_credentials(token, zone_id, domain):
    with open(CRED_FILE, "w") as f:
        json.dump({"token": token, "zone_id": zone_id, "domain": domain}, f)
    print("✅ Credentials saved.\n")

def load_credentials():
    if os.path.exists(CRED_FILE):
        with open(CRED_FILE, "r") as f:
            return json.load(f)
    return None

def delete_credentials():
    if os.path.exists(CRED_FILE):
        os.remove(CRED_FILE)
        print("🔒 Closing session...")
        time.sleep(0.4)
        print("👋 Logged out successfully.\n")

def get_auth():
    creds = load_credentials()
    if creds:
        print(f"🔐 Auto login → {creds['domain']}\n")
        return creds["token"], creds["zone_id"], creds["domain"]

    print("🔑 Cloudflare Login Required:")
    token = getpass.getpass("Enter API Token: ").strip()
    zone_id = input("Enter Zone ID: ").strip()
    domain = input("Enter Domain: ").strip()
    save_q = input("Save credentials for future use? (y/n): ").lower()
    if save_q == "y":
        save_credentials(token, zone_id, domain)
    return token, zone_id, domain

# -----------------------
# CLOUDFLARE HELPERS
# -----------------------

def cf_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

def cf_get(session, url, params=None):
    return session.get(url, params=params)

def cf_post(session, url, payload):
    return session.post(url, json=payload)

def cf_put(session, url, payload):
    return session.put(url, json=payload)

def cf_delete(session, url):
    return session.delete(url)

def list_dns(session, zone_id):
    # grab first 100 only for now (Cloudflare default per_page=100)
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records")
    data = r.json()
    return data.get("result", [])

def get_zone_status(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    if r.status_code == 200:
        status = r.json().get("result", {}).get("status", "")
        # treat suspended/locked/etc as flagged
        if status in ["suspended", "locked", "hold"]:
            return 1
        return 0
    return 0

def natural_sort_key(name: str):
    """
    Makes sure us1, us2, us10 sort in numeric order
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(r'([0-9]+)', name)]

# -----------------------
# INPUT HELPERS
# -----------------------

def timed_input_list(prompt="Paste IPs (one per line). Press Enter twice to finish:"):
    print(prompt)
    lines = []
    while True:
        line = input().strip()
        if line == "":
            break
        lines.append(line)
    return lines

# -----------------------
# FEATURE: CREATE DNS (SERIAL PREFIX)
# -----------------------

def create_dns_records(session, zone_id, domain):
    base = input("\nBase name (us/uk/ca/custom): ").strip().lower()
    ips = timed_input_list("Paste IPs (one per line). Press Enter twice to finish:")
    if not ips:
        print("❌ No IPs provided. Cancelled.\n")
        return

    start_t = time.perf_counter()
    total = len(ips)
    print("\n⚙️ Creating DNS Records...\n")

    for idx, ip in enumerate(ips, start=1):
        sub = f"{base}{idx}.{domain}"
        progress_bar(idx, total, prefix="⚙️ Creating")
        payload = {
            "type": "A",
            "name": sub,
            "content": ip,
            "ttl": 1,
            "proxied": False
        }
        resp = cf_post(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", payload)
        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            print(resp.text)

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# -----------------------
# FEATURE: CREATE DNS (RANDOM NAMES 5-8 chars)
# -----------------------

def random_label():
    length = random.randint(5, 8)
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

def create_dns_random(session, zone_id, domain):
    ips = timed_input_list("Paste IPs (one per line). Press Enter twice to finish:")
    if not ips:
        print("❌ No IPs provided. Cancelled.\n")
        return

    start_t = time.perf_counter()
    total = len(ips)
    print("\n⚙️ Creating DNS Records (Random)...\n")

    for idx, ip in enumerate(ips, start=1):
        sub = f"{random_label()}.{domain}"
        progress_bar(idx, total, prefix="⚙️ Creating")
        payload = {
            "type": "A",
            "name": sub,
            "content": ip,
            "ttl": 1,
            "proxied": False
        }
        resp = cf_post(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", payload)
        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            print(resp.text)

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# -----------------------
# FEATURE: DELETE DNS
# -----------------------

def delete_dns(session, zone_id):
    print("\n🧹 DNS Delete Menu")
    print("1) Delete by Name")
    print("2) Delete ALL Records")
    print("3) Back")
    choice = input("Choose: ").strip()

    if choice == "1":
        name = input("Enter full DNS name to delete: ").strip()
        if not name:
            print("❌ No name given.\n")
            return
        spin_stop = spinner_start("🗑️ Deleting record")
        r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", params={"name": name})
        data = r.json()
        results = data.get("result", [])
        if not results:
            spin_stop()
            print("❌ Not found.\n")
            return
        rid = results[0]["id"]
        d = cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
        spin_stop()
        if d.status_code == 200 and d.json().get("success"):
            print(f"🗑️ Deleted: {name}\n")
        else:
            print("❌ Delete failed.\n")
        return

    if choice == "2":
        c1 = input("⚠️ Delete ALL DNS records? (y/n): ").lower()
        if c1 != "y":
            print("❌ Cancelled.\n")
            return
        c2 = input("Confirm again (y/n): ").lower()
        if c2 != "y":
            print("❌ Cancelled.\n")
            return

        recs = list_dns(session, zone_id)
        total = len(recs)
        print(f"\n🧹 Deleting {total} DNS records...\n")
        start_t = time.perf_counter()

        for idx, rec in enumerate(recs, start=1):
            rid = rec["id"]
            nm = rec["name"]
            progress_bar(idx, total, prefix="🗑️ Removing")
            cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
            print(f"\n🗑️ Deleted: {nm}")

        total_time = time.perf_counter() - start_t
        print(f"\n✅ Total Deleted: {total}")
        print(f"⏱ Time: {total_time:.2f}s\n")
        return

    if choice == "3":
        return

# -----------------------
# FEATURE: LIST DNS (NORMAL)
# -----------------------

def list_normal(session, zone_id):
    spin_stop = spinner_start("⏳ Loading DNS Records")
    recs = list_dns(session, zone_id)
    spin_stop()
    print("✅ DNS Records Loaded.\n")

    lines = []
    for r in recs:
        nm = r.get("name", "")
        ip = r.get("content", "")
        line = f"{nm} {ip}"
        lines.append(line)
        print(line)

    with open("dns_list_normal.txt", "w") as f:
        for line in lines:
            f.write(line + "\n")

    print("\n📄 Saved to dns_list_normal.txt\n")

# -----------------------
# FEATURE: LIST DNS (PRO VIEW)
# -----------------------

def list_pro(session, zone_id):
    # animated load
    spin_stop = spinner_start("⏳ Loading DNS Records")
    recs = list_dns(session, zone_id)
    spin_stop()
    print("✅ DNS Records Loaded Successfully!\n")

    # group by prefix
    groups = {}
    for r in recs:
        full = r.get("name", "")
        first_label = full.split(".")[0] if full else ""
        m = re.match(r"^([a-zA-Z]+)", first_label)
        prefix = m.group(1).lower() if m else "other"
        groups.setdefault(prefix, []).append(full)

    # serialize with numeric order
    with open("dns_list_pro.txt", "w") as f:
        for prefix, names in groups.items():
            names.sort(key=natural_sort_key)
            flag = FLAG_MAP.get(prefix.lower(), "🏳️")
            joined = "~".join(names)

            print(f"{flag}  {prefix.upper()}")
            print(joined + "\n")

            f.write(f"{prefix.upper()}\n")
            f.write(joined + "\n\n")

    print("📄 Saved to dns_list_pro.txt\n")

# -----------------------
# (OPTIONAL) EXTRA FEATURES:
# Name Server Manager / SSL / Tools
# For now, showing stubs (visual hooks ready)
# -----------------------

def tools_menu(session, zone_id, domain):
    while True:
        print("\n🛠 Tools Menu")
        print("1) Domain Add")
        print("2) Domain Remove (clear all DNS)")
        print("3) Abuse Check")
        print("4) Back")
        c = input("Choose: ").strip()

        if c == "1":
            new_domain = input("Enter new domain to add: ").strip()
            if not new_domain:
                print("❌ No domain.\n")
                continue
            spin_stop = spinner_start("🧩 Adding Domain")
            resp = cf_post(session, "https://api.cloudflare.com/client/v4/zones",
                           {"name": new_domain, "jump_start": True})
            spin_stop()
            if resp.status_code == 200 and resp.json().get("success"):
                result = resp.json().get("result", {})
                print("✅ Domain added.")
                print("Zone ID:", result.get("id"))
                print("Status :", result.get("status"), "\n")
                with open("added_domains.txt", "a") as f:
                    f.write(f"{datetime.utcnow().isoformat()} {new_domain} {result.get('id')} {result.get('status')}\n")
            else:
                print("❌ Failed to add domain.\n")
                print(resp.text + "\n")

        elif c == "2":
            confirm = input(f"⚠️ Clear ALL DNS for {domain}? (y/n): ").lower()
            if confirm != "y":
                print("❌ Cancelled.\n")
                continue
            confirm2 = input("Confirm again (y/n): ").lower()
            if confirm2 != "y":
                print("❌ Cancelled.\n")
                continue

            spin_stop = spinner_start("🧹 Cleaning Domain")
            recs = list_dns(session, zone_id)
            spin_stop()

            total = len(recs)
            print(f"\n🧹 Deleting {total} DNS records...\n")
            start_t = time.perf_counter()

            for idx, rec in enumerate(recs, start=1):
                rid = rec["id"]
                nm = rec["name"]
                progress_bar(idx, total, prefix="🗑️ Removing")
                cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
                print(f"\n🗑️ Deleted: {nm}")

            total_time = time.perf_counter() - start_t
            print(f"\n✅ Domain cleaned. Total Removed: {total}")
            print(f"⏱ Time: {total_time:.2f}s\n")

            with open("domain_remove_log.txt", "a") as f:
                f.write(f"{datetime.utcnow().isoformat()} {domain} removed {total} records\n")

        elif c == "3":
            spin_stop = spinner_start("🔍 Scanning for Abuse")
            status_flag = get_zone_status(session, zone_id)
            spin_stop()
            if status_flag == 0:
                print("✅ Clean. No abuse/suspension detected.\n")
            else:
                print("⚠️ Possible suspension / hold detected.\n")

        elif c == "4":
            break

        else:
            print("❌ Invalid.\n")

# (stubs: can be expanded like before if wanted)
def nameserver_manager():
    print("\nℹ Name Server Manager not expanded in v9.4 yet.\n")

def ssl_manager():
    print("\nℹ SSL/TLS Mode Manager not expanded in v9.4 yet.\n")

# -----------------------
# MAIN MENU LOOP
# -----------------------

def main():
    creds = load_credentials()
    if creds:
        token, zone_id, domain = creds["token"], creds["zone_id"], creds["domain"]
    else:
        token, zone_id, domain = get_auth()

    session = requests.Session()
    session.headers.update(cf_headers(token))

    while True:
        abuse_flag = get_zone_status(session, zone_id)
        total_dns = len(list_dns(session, zone_id))

        print("\n╭────────────────────────────────────────────╮")
        print("│ Cloudflare DNS Manager v9.4 — MHR Edition │")
        print("│   Developed by MHR Dev Team               │")
        print("╰────────────────────────────────────────────╯\n")

        print(f" Domain              : {domain}")
        print(f" Total DNS Available : {total_dns}")
        print(f" Abuse Status        : {abuse_flag}")
        print(DIV)
        print(" [1] Create DNS Records")
        print(" [2] Create DNS (Random)")
        print(" [3] Delete DNS Records")
        print(" [4] DNS List (Normal View)")
        print(" [5] DNS List (Pro View)")
        print(" [6] Name Server Manager")
        print(" [7] SSL/TLS Mode Manager")
        print(" [8] Tools")
        print(" [9] Logout")
        print(" [10] Exit")
        print(DIV)

        choice = input(" Select Option (1-10): ").strip()

        if choice == "1":
            create_dns_records(session, zone_id, domain)

        elif choice == "2":
            create_dns_random(session, zone_id, domain)

        elif choice == "3":
            delete_dns(session, zone_id)

        elif choice == "4":
            list_normal(session, zone_id)

        elif choice == "5":
            list_pro(session, zone_id)

        elif choice == "6":
            nameserver_manager()

        elif choice == "7":
            ssl_manager()

        elif choice == "8":
            tools_menu(session, zone_id, domain)

        elif choice == "9":
            delete_credentials()
            break

        elif choice == "10":
            print("👋 Exiting...")
            time.sleep(0.4)
            break

        else:
            print("❌ Invalid option.\n")

if __name__ == "__main__":
    main()
