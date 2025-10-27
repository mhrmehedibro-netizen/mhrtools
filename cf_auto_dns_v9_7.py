#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════
#  Cloudflare DNS Manager v9.7 — MHR Full Unified Build
#  Made by MHR 🌿
#  Developed & Maintained by MHR Dev Team
#  Features:
#   - Auto Login & Logout
#   - Permission Checker (--check-token)
#   - DNS Create / Random Create / Delete / List (Normal+Pro)
#   - Sorted Pro View with Flag Groups
#   - Tools: Domain Add / Domain Remove / Abuse Check
#   - Nameserver Viewer
#   - SSL/TLS Mode Manager (with safe permission handling)
#   - Animated spinner + progress bar
# ════════════════════════════════════════════════════════════════════

import requests, json, os, sys, time, getpass, random, string, re, itertools, threading
from datetime import datetime

CRED_FILE = "credentials.json"
DIV      = "────────────────────────────────────────────"

FLAG_MAP = {
    "us": "🇺🇸",
    "uk": "🇬🇧",
    "ca": "🇨🇦",
    "de": "🇩🇪",
    "fr": "🇫🇷",
    "jp": "🇯🇵",
    "in": "🇮🇳",
}

# ─────────────────────────────────
# Animation helpers
# ─────────────────────────────────

def spinner_start(text="Processing"):
    """
    start spinner in background, return stop() function
    shows: <text> | / - \
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
        time.sleep(0.15)

    return stop

def progress_bar(current, total, prefix=""):
    """
    ⚙️ Creating (3/10) |██████░░░░░░| 60%
    compact short bar, per-step feedback
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

# ─────────────────────────────────
# Helpers: sorting, input batching
# ─────────────────────────────────

def natural_sort_key(name: str):
    """
    Ensures us1, us2, us10 sorts in numeric order,
    not (us1, us10, us2)
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(r'([0-9]+)', name)]

def timed_input_list(prompt="Paste IPs (one per line). Press Enter twice to finish:"):
    print(prompt)
    lines = []
    while True:
        line = input().strip()
        if line == "":
            break
        lines.append(line)
    return lines

def random_label():
    length = random.randint(5, 8)
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

# ─────────────────────────────────
# Credential / auth handling
# ─────────────────────────────────

def cf_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

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
    token   = getpass.getpass("Enter API Token: ").strip()
    zone_id = input("Enter Zone ID: ").strip()
    domain  = input("Enter Domain: ").strip()
    save_q  = input("Save credentials for future use? (y/n): ").lower()
    if save_q == "y":
        save_credentials(token, zone_id, domain)
    return token, zone_id, domain

# ─────────────────────────────────
# Cloudflare request helpers
# ─────────────────────────────────

def cf_get(session, url, params=None):
    return session.get(url, params=params)

def cf_post(session, url, payload):
    return session.post(url, json=payload)

def cf_put(session, url, payload):
    return session.put(url, json=payload)

def cf_patch(session, url, payload):
    return session.patch(url, json=payload)

def cf_delete(session, url):
    return session.delete(url)

def list_dns(session, zone_id):
    # first page default 100
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records")
    data = r.json()
    return data.get("result", [])

def get_zone_status(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    if r.status_code == 200:
        status = r.json().get("result", {}).get("status", "")
        # treat suspended / locked / hold as flagged
        if status in ["suspended", "locked", "hold"]:
            return 1
        return 0
    return 0

# ─────────────────────────────────
# Permission checker
# ─────────────────────────────────

def check_token_permissions(token):
    print("\n🔍 Checking Cloudflare Token Permissions...")
    stop = spinner_start("Verifying")
    headers = cf_headers(token)
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    r = requests.get(url, headers=headers)
    stop()

    if r.status_code != 200:
        print("❌ Failed to verify token (HTTP error).\n")
        return

    data = r.json()
    if not data.get("success"):
        print("❌ Invalid API token.\n")
        return

    policies = data["result"].get("policies", [])
    print("\n✅ Token Verified. Permissions:")
    for p in policies:
        for perm in p.get("permission_groups", []):
            print("  •", perm.get("name"))
    print("\n📜 Permission check complete!\n")

# ─────────────────────────────────
# DNS Create (serial prefix)
# ─────────────────────────────────

def create_dns_records(session, zone_id, domain):
    base = input("\nBase name (us/uk/ca/custom): ").strip().lower()
    ips  = timed_input_list("Paste IPs (one per line). Press Enter twice to finish:")
    if not ips:
        print("❌ No IPs provided. Cancelled.\n")
        return

    start_t = time.perf_counter()
    total   = len(ips)
    print("\n⚙️ Creating DNS Records...\n")

    for idx, ip in enumerate(ips, start=1):
        sub = f"{base}{idx}.{domain}"
        progress_bar(idx, total, prefix="⚙️ Creating")
        payload = {
            "type":    "A",
            "name":    sub,
            "content": ip,
            "ttl":     1,
            "proxied": False
        }
        resp = cf_post(session,
                       f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                       payload)
        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            print(resp.text)

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# ─────────────────────────────────
# DNS Create (random labels 5-8 char)
# ─────────────────────────────────

def create_dns_random(session, zone_id, domain):
    ips  = timed_input_list("Paste IPs (one per line). Press Enter twice to finish:")
    if not ips:
        print("❌ No IPs provided. Cancelled.\n")
        return

    start_t = time.perf_counter()
    total   = len(ips)
    print("\n⚙️ Creating DNS Records (Random)...\n")

    for idx, ip in enumerate(ips, start=1):
        sub = f"{random_label()}.{domain}"
        progress_bar(idx, total, prefix="⚙️ Creating")
        payload = {
            "type":    "A",
            "name":    sub,
            "content": ip,
            "ttl":     1,
            "proxied": False
        }
        resp = cf_post(session,
                       f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                       payload)
        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            print(resp.text)

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# ─────────────────────────────────
# DNS Delete Menu
# ─────────────────────────────────

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
        stop = spinner_start("🗑️ Deleting record")
        r = cf_get(session,
                   f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                   params={"name": name})
        data = r.json()
        results = data.get("result", [])
        if not results:
            stop()
            print("❌ Not found.\n")
            return
        rid = results[0]["id"]
        d   = cf_delete(session,
                        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
        stop()
        if d.status_code == 200 and d.json().get("success"):
            print(f"🗑️ Deleted: {name}\n")
        else:
            print("❌ Delete failed.\n")
        return

    if choice == "2":
        c1 = input("⚠️ Delete ALL DNS records? (y/n): ").lower()
        if c1 != "y":
            print("❌ Cancelled.\n"); return
        c2 = input("Confirm again (y/n): ").lower()
        if c2 != "y":
            print("❌ Cancelled.\n"); return

        recs = list_dns(session, zone_id)
        total = len(recs)
        print(f"\n🧹 Deleting {total} DNS records...\n")
        start_t = time.perf_counter()

        for idx, rec in enumerate(recs, start=1):
            rid = rec["id"]
            nm  = rec["name"]
            progress_bar(idx, total, prefix="🗑️ Removing")
            cf_delete(session,
                      f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
            print(f"\n🗑️ Deleted: {nm}")

        total_time = time.perf_counter() - start_t
        print(f"\n✅ Total Deleted: {total}")
        print(f"⏱ Time: {total_time:.2f}s\n")
        return

    if choice == "3":
        return

# ─────────────────────────────────
# DNS List (Normal View)
# ─────────────────────────────────

def list_normal(session, zone_id):
    stop = spinner_start("⏳ Loading DNS Records")
    recs = list_dns(session, zone_id)
    stop()
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

# ─────────────────────────────────
# DNS List (Pro View) – flags + sorted
# ─────────────────────────────────

def list_pro(session, zone_id):
    stop = spinner_start("⏳ Loading DNS Records")
    recs = list_dns(session, zone_id)
    stop()
    print("✅ DNS Records Loaded Successfully!\n")

    groups = {}
    for r in recs:
        full = r.get("name", "")
        first_label = full.split(".")[0] if full else ""
        m = re.match(r"^([a-zA-Z]+)", first_label)
        prefix = m.group(1).lower() if m else "other"
        groups.setdefault(prefix, []).append(full)

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

# ─────────────────────────────────
# Nameserver Manager (Option 6)
# ─────────────────────────────────

def show_nameservers(session, zone_id):
    print("\n🔍 Fetching Cloudflare Nameservers...")
    stop = spinner_start("📡 Getting nameservers")
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    stop()

    if r.status_code != 200:
        print("❌ Failed to fetch nameservers (HTTP error).\n")
        input("Press Enter to return...")
        return

    data = r.json()
    if not data.get("success"):
        print("❌ Failed to fetch nameservers (API error).\n")
        input("Press Enter to return...")
        return

    ns_list = data["result"].get("name_servers", [])
    if not ns_list:
        print("⚠ No nameservers found (zone may not be active yet).\n")
        input("Press Enter to return...")
        return

    print("\n📡 Current Cloudflare Nameservers:")
    for i, ns in enumerate(ns_list, start=1):
        print(f" {i}. {ns}")
    print("\n✅ Nameservers fetched successfully!\n")
    input("Press Enter to return to main menu...")

# ─────────────────────────────────
# SSL/TLS Mode Manager (Option 7)
# ─────────────────────────────────

def ssl_tls_mode_manager(session, zone_id):
    print("\n🔐 Checking current SSL/TLS Mode...")
    stop = spinner_start("🔍 Fetching SSL mode")
    r = session.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl")
    stop()

    if r.status_code == 403:
        print("⚠ Missing Zone Settings:Edit permission. Please recreate token.\n")
        input("Press Enter to return...")
        return
    if r.status_code != 200:
        print("❌ Failed to fetch SSL mode (HTTP error).\n")
        input("Press Enter to return...")
        return

    data = r.json()
    if not data.get("success"):
        print("❌ Failed to fetch SSL mode (API error).\n")
        input("Press Enter to return...")
        return

    current_mode = data["result"]["value"].capitalize()
    print(f"🌐 Current SSL/TLS Mode: {current_mode}\n")
    print("Available Modes:\n 1) Flexible\n 2) Full\n 3) Strict\n")
    choice = input("Select new mode (1-3) or Enter to skip: ").strip()

    mode_map = {"1": "flexible", "2": "full", "3": "strict"}
    if choice not in mode_map:
        print("⚠ No change applied.\n")
        input("Press Enter to return...")
        return

    new_mode = mode_map[choice]
    print(f"🔄 Updating to {new_mode.capitalize()}...")
    stop = spinner_start("⚙️ Applying")
    r2 = session.patch(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl",
        headers=session.headers,
        json={"value": new_mode}
    )
    stop()

    if r2.status_code == 403:
        print("⚠ Missing Zone Settings:Edit permission. Cannot update SSL mode.\n")
    elif r2.status_code == 200 and r2.json().get("success"):
        print(f"✅ SSL/TLS mode changed to {new_mode.capitalize()}.\n")
    else:
        print("❌ Failed to update SSL mode.\n")

    input("Press Enter to return to main menu...")

# ─────────────────────────────────
# Tools Menu (Option 8)
# ─────────────────────────────────

def tools_menu(session, zone_id, domain):
    while True:
        print("\n🛠 Tools Menu")
        print("1) Domain Add")
        print("2) Domain Remove (clear ALL DNS)")
        print("3) Abuse Check")
        print("4) Back")
        c = input("Choose: ").strip()

        if c == "1":
            new_domain = input("Enter new domain to add: ").strip()
            if not new_domain:
                print("❌ No domain.\n")
                continue
            stop = spinner_start("🧩 Adding Domain")
            resp = cf_post(session,
                           "https://api.cloudflare.com/client/v4/zones",
                           {"name": new_domain, "jump_start": True})
            stop()
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

            stop = spinner_start("🧹 Cleaning Domain")
            recs = list_dns(session, zone_id)
            stop()

            total = len(recs)
            print(f"\n🧹 Deleting {total} DNS records...\n")
            start_t = time.perf_counter()

            for idx, rec in enumerate(recs, start=1):
                rid = rec["id"]
                nm  = rec["name"]
                progress_bar(idx, total, prefix="🗑️ Removing")
                cf_delete(session,
                          f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
                print(f"\n🗑️ Deleted: {nm}")

            total_time = time.perf_counter() - start_t
            print(f"\n✅ Domain cleaned. Total Removed: {total}")
            print(f"⏱ Time: {total_time:.2f}s\n")

            with open("domain_remove_log.txt", "a") as f:
                f.write(f"{datetime.utcnow().isoformat()} {domain} removed {total} records\n")

        elif c == "3":
            stop = spinner_start("🔍 Scanning for Abuse / Suspension")
            status_flag = get_zone_status(session, zone_id)
            stop()
            if status_flag == 0:
                print("✅ Clean. No abuse/suspension detected.\n")
            else:
                print("⚠️ Possible suspension / hold detected.\n")

        elif c == "4":
            break

        else:
            print("❌ Invalid.\n")

# ─────────────────────────────────
# Main Menu Loop
# ─────────────────────────────────

def main():
    # fast path: only permission test, no menu
    if len(sys.argv) > 1 and sys.argv[1] == "--check-token":
        token = getpass.getpass("Enter Cloudflare API Token: ").strip()
        check_token_permissions(token)
        return

    creds = load_credentials()
    if creds:
        token, zone_id, domain = creds["token"], creds["zone_id"], creds["domain"]
    else:
        token, zone_id, domain = get_auth()

    session = requests.Session()
    session.headers.update(cf_headers(token))

    while True:
        abuse_flag = get_zone_status(session, zone_id)
        total_dns  = len(list_dns(session, zone_id))

        print("\n╭────────────────────────────────────────────╮")
        print("│ Cloudflare DNS Manager v9.7 — MHR Edition │")
        print("│   Developed by MHR Dev Team 🌿            │")
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
        print(" [9] Check Token Permissions")
        print(" [10] Logout")
        print(" [11] Exit")
        print(DIV)

        choice = input(" Select Option (1-11): ").strip()

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
            show_nameservers(session, zone_id)
        elif choice == "7":
            ssl_tls_mode_manager(session, zone_id)
        elif choice == "8":
            tools_menu(session, zone_id, domain)
        elif choice == "9":
            check_token_permissions(token)
        elif choice == "10":
            delete_credentials()
            break
        elif choice == "11":
            print("👋 Exiting...")
            time.sleep(0.4)
            break
        else:
            print("❌ Invalid option.\n")

if __name__ == "__main__":
    main()
