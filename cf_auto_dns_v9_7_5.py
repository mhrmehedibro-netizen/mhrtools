#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════
#  Cloudflare DNS Manager v9.7.5 — Permission Guard Edition
#  Made by MHR 🌿
#  Developed & Maintained by MHR Dev Team
#
#  Highlights:
#   - Auto Login / Logout (credentials.json)
#   - Startup Permission Guard (checks token permissions before menu)
#   - DNS Create (serial prefix) / DNS Create (random labels)
#   - DNS Delete (single / wipe-all with confirm 2x)
#   - DNS List (Normal / Pro) with nice grouping + flags + natural sort
#   - Name Server Manager (view Cloudflare nameservers)
#   - SSL/TLS Mode Manager (view + update; permission aware)
#   - Tools Menu:
#         [1] Add Specific Domain        (POST /zones)
#         [2] Remove Specific Domain     (DELETE /zones/:id)
#         [3] Abuse Check                (zone status)
#         [4] Check Token Permissions    (tokens/verify)
#         [5] Show All Domains           (list zones)
#   - Domain add/remove logged to domain_activity_log.txt
#   - Spinner + Progress bar animations everywhere
#
#  REQUIREMENTS on a fresh Debian VPS:
#     apt update -y && apt install -y python3 python3-pip
#     pip3 install requests
#
#  USAGE:
#     python3 cf_auto_dns_v9_7_5.py
#     python3 cf_auto_dns_v9_7_5.py --check-token
#
# ════════════════════════════════════════════════════════════════════

import requests, json, os, sys, time, getpass, random, string, re, itertools, threading
from datetime import datetime

CRED_FILE = "credentials.json"
DIV       = "────────────────────────────────────────────"

# prefix -> flag (used in Pro DNS list)
FLAG_MAP = {
    "us": "🇺🇸",
    "uk": "🇬🇧",
    "ca": "🇨🇦",
    "de": "🇩🇪",
    "fr": "🇫🇷",
    "jp": "🇯🇵",
    "in": "🇮🇳",
}

# ═════════════════════════════════════════
# Spinner + Progress visuals
# ═════════════════════════════════════════

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
        time.sleep(0.15)

    return stop


def progress_bar(current, total, prefix=""):
    """
    Compact progress bar: ⚙️ Creating (3/10) |██████░░░░░░| 60%
    """
    width  = 12
    ratio  = (current / total) if total else 1
    filled = int(ratio * width)
    bar    = "█" * filled + "░" * (width - filled)
    pct    = int(ratio * 100)
    sys.stdout.write(f"\r{prefix} ({current}/{total}) |{bar}| {pct}%")
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")

# ═════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════

def natural_sort_key(name: str):
    """
    Sort like us1, us2, us10 instead of us1, us10, us2
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
    chars  = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

# ═════════════════════════════════════════
# Credentials / Auth
# ═════════════════════════════════════════

def cf_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
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

# ═════════════════════════════════════════
# Cloudflare basic helpers (requests)
# ═════════════════════════════════════════

def cf_get(session, url, params=None):
    return session.get(url, params=params)

def cf_post(session, url, payload):
    return session.post(url, json=payload)

def cf_patch(session, url, payload):
    return session.patch(url, json=payload)

def cf_delete(session, url):
    return session.delete(url)

def list_dns(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records")
    data = r.json()
    return data.get("result", [])

def get_zone_status(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    if r.status_code == 200:
        status = r.json().get("result", {}).get("status", "")
        # suspended / locked / hold => treat as abuse 1
        if status in ["suspended", "locked", "hold"]:
            return 1
        return 0
    return 0

# ═════════════════════════════════════════
# Domain / Zone helpers
# ═════════════════════════════════════════

def list_all_domains(session):
    """
    Return list of zones as dicts {id,name,status}
    """
    r = cf_get(session, "https://api.cloudflare.com/client/v4/zones")
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"
    data = r.json()
    if not data.get("success"):
        return None, "API error"
    zones = data.get("result", [])
    out = []
    for z in zones:
        out.append({
            "id": z.get("id", ""),
            "name": z.get("name", ""),
            "status": z.get("status", "")
        })
    return out, None

def add_specific_domain(session, new_domain):
    """
    Add ONLY root domain (example.com), not subdomain.
    Cloudflare API: POST /zones
    """
    # prevent subdomain by quick check:
    if new_domain.count(".") < 1:
        print("❌ Invalid domain format.\n")
        return
    if new_domain.count(".") >= 2:
        # e.g. vboss4.ggff.net (subdomain)
        # Cloudflare won't accept as zone
        print("⚠ This looks like a subdomain.")
        print("  You can NOT add subdomain as new zone.")
        print("  To create subdomain, use 'Create DNS Records'.\n")
        return

    stop = spinner_start("🧩 Adding Domain")
    resp = cf_post(
        session,
        "https://api.cloudflare.com/client/v4/zones",
        {"name": new_domain, "jump_start": True}
    )
    stop()

    if resp.status_code == 200 and resp.json().get("success"):
        result = resp.json().get("result", {})
        zone_id = result.get("id")
        status  = result.get("status")
        print("✅ Domain added.")
        print("   Domain :", new_domain)
        print("   Zone ID:", zone_id)
        print("   Status :", status, "\n")
        # log this
        with open("domain_activity_log.txt", "a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}] ADDED {new_domain} zone_id={zone_id} status={status}\n")
    else:
        print("❌ Failed to add domain.\n")
        print(resp.text + "\n")

def remove_specific_domain(session):
    """
    1. show list of zones
    2. choose a zone
    3. DELETE /zones/:id
    """
    zones, err = list_all_domains(session)
    if err or zones is None:
        print(f"❌ Could not list domains ({err}).\n")
        return

    if not zones:
        print("⚠ No domains found on this token.\n")
        return

    print(f"\n🌐 Total Domains: {len(zones)}")
    print("────────────────────────────")
    for i, z in enumerate(zones, start=1):
        print(f"{i}) {z['name']}  → {z['status']}  [{z['id']}]")
    print("────────────────────────────\n")

    pick = input("Enter number to remove (or Enter to cancel): ").strip()
    if not pick.isdigit():
        print("❌ Cancelled.\n")
        return

    idx = int(pick)
    if idx < 1 or idx > len(zones):
        print("❌ Invalid selection.\n")
        return

    target = zones[idx-1]
    dom    = target["name"]
    zid    = target["id"]

    sure = input(f"⚠ Really DELETE zone {dom}? (y/n): ").lower()
    if sure != "y":
        print("❌ Cancelled.\n")
        return

    stop = spinner_start("🗑️ Deleting Domain Zone")
    resp = cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zid}")
    stop()

    if resp.status_code == 200 and resp.json().get("success"):
        print(f"🗑️ Domain removed: {dom} (zone_id={zid})\n")
        with open("domain_activity_log.txt", "a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}] REMOVED {dom} zone_id={zid}\n")
    else:
        print("❌ Failed to remove domain.\n")
        print(resp.text + "\n")

def show_all_domains(session):
    """
    List all domains in account + save to domain_list.txt
    """
    zones, err = list_all_domains(session)
    if err or zones is None:
        print(f"❌ Could not list domains ({err}).\n")
        return

    if not zones:
        print("⚠ No domains found on this token.\n")
        return

    print(f"\n🌐 Total Domains: {len(zones)}")
    print("────────────────────────────")
    lines = []
    for i, z in enumerate(zones, start=1):
        line = f"{i}) {z['name']}  → {z['status']}  [zone_id={z['id']}]"
        lines.append(line)
        print(line)
    print("────────────────────────────\n")

    with open("domain_list.txt", "w") as f:
        for L in lines:
            f.write(L + "\n")

    print("📄 Saved to domain_list.txt\n")

# ═════════════════════════════════════════
# Permission checker + validator
# ═════════════════════════════════════════

def check_token_permissions_raw(token):
    """
    Low-level checker (no prompts). Returns (success, http_code, perms_list or err_msg)
    perms_list is list[str] of permission group names
    """
    headers = cf_headers(token)
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        return False, r.status_code, f"HTTP {r.status_code}"

    data = r.json()
    if not data.get("success"):
        return False, 200, "Token invalid"

    policies = data["result"].get("policies", [])
    perms_list = []
    for p in policies:
        for perm in p.get("permission_groups", []):
            name = perm.get("name")
            if name:
                perms_list.append(name)
    return True, 200, perms_list

def check_token_permissions_display(token):
    """
    Interactive pretty view (used in Tools -> Check Token Permissions)
    """
    print("\n🔍 Checking Cloudflare Token Permissions...")
    stop = spinner_start("Verifying")
    ok, code, payload = check_token_permissions_raw(token)
    stop()

    if not ok:
        print("❌ Failed to verify token.")
        print(f"   Detail: {payload}\n")
        return

    perms_list = payload
    print("\n✅ Token Verified. Permissions:")
    if not perms_list:
        print("   (No explicit policy list from API)")
    else:
        for p in perms_list:
            print("  •", p)
    print("\n📜 Permission check complete!\n")

def permission_guard(token):
    """
    Run at startup.
    We define required keywords that should appear in permission names.
    If missing, warn user and allow continue or exit.
    """
    required_keywords = [
        "Zone Read",
        "Zone Edit",
        "Zone Settings Read",
        "Zone Settings Edit",
        "DNS Read",
        "DNS Edit",
        "SSL and Certificates Edit",
        "User Details Read",
        "User Read",  # fallback name
    ]

    print("🔍 Checking Cloudflare Token Permissions...")
    stop = spinner_start("Verifying")
    ok, code, payload = check_token_permissions_raw(token)
    stop()

    if not ok:
        print("❌ Could not verify token permissions.")
        print(f"   Detail: {payload}")
        ans = input("Continue anyway? (y/n): ").strip().lower()
        if ans != "y":
            sys.exit(1)
        return

    perms_list = payload  # list of permission group names from CF
    # build a simple text blob to match keywords against
    blob = " | ".join(perms_list)

    missing_any = False
    missing_list = []
    # We'll treat 'User Details Read' and 'User Read' as same family
    normalized_reqs = [
        ("Zone Read",            ["Zone Read"]),
        ("Zone Edit",            ["Zone Edit"]),
        ("Zone Settings Read",   ["Zone Settings Read", "Zone Settings:Read"]),
        ("Zone Settings Edit",   ["Zone Settings Edit", "Zone Settings:Edit"]),
        ("DNS Read",             ["DNS Read", "Zone DNS Read"]),
        ("DNS Edit",             ["DNS Edit", "Zone DNS Edit"]),
        ("SSL and Certificates Edit", ["SSL and Certificates Edit", "SSL Edit", "SSL and Certificates:Edit"]),
        ("User Read",            ["User Read", "User Details Read", "User Details:Read", "User Details Read permission"]),
    ]

    for human_name, patterns in normalized_reqs:
        found = False
        for pat in patterns:
            if pat.lower() in blob.lower():
                found = True
                break
        if not found:
            missing_any = True
            missing_list.append(human_name)

    if not missing_any:
        print("✅ All required permissions verified!\n")
        return

    print("⚠ Missing Permissions Detected:")
    for m in missing_list:
        print("  -", m)

    print("\nThese permissions are needed for full control (DNS edit, SSL/TLS change, zone add/remove).")
    ans = input("Continue anyway? (y/n): ").strip().lower()
    if ans != "y":
        print("👋 Exiting due to insufficient permissions.")
        sys.exit(1)

# ═════════════════════════════════════════
# DNS Create (serial prefix e.g. us1, us2...)
# ═════════════════════════════════════════

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

        resp = cf_post(
            session,
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            payload
        )

        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            print(resp.text)

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# ═════════════════════════════════════════
# DNS Create (random label 5–8 char)
# ═════════════════════════════════════════

def create_dns_random(session, zone_id, domain):
    ips = timed_input_list("Paste IPs (one per line). Press Enter twice to finish:")
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

        resp = cf_post(
            session,
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            payload
        )

        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            print(resp.text)

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# ═════════════════════════════════════════
# DNS Delete
# ═════════════════════════════════════════

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
        r = cf_get(
            session,
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            params={"name": name}
        )
        data = r.json()
        results = data.get("result", [])
        if not results:
            spin_stop()
            print("❌ Not found.\n")
            return

        rid = results[0]["id"]
        d   = cf_delete(
            session,
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}"
        )
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
            nm  = rec["name"]
            progress_bar(idx, total, prefix="🗑️ Removing")

            cf_delete(
                session,
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}"
            )

            print(f"\n🗑️ Deleted: {nm}")

        total_time = time.perf_counter() - start_t
        print(f"\n✅ Total Deleted: {total}")
        print(f"⏱ Time: {total_time:.2f}s\n")
        return

    if choice == "3":
        return

# ═════════════════════════════════════════
# DNS List (Normal)
# ═════════════════════════════════════════

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

# ═════════════════════════════════════════
# DNS List (Pro)
# ═════════════════════════════════════════

def list_pro(session, zone_id):
    spin_stop = spinner_start("⏳ Loading DNS Records")
    recs = list_dns(session, zone_id)
    spin_stop()
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

# ═════════════════════════════════════════
# Name Server Manager (Option 6)
# ═════════════════════════════════════════

def show_nameservers(session, zone_id):
    print("\n🔍 Fetching Cloudflare Nameservers...")
    spin_stop = spinner_start("📡 Getting nameservers")
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    spin_stop()

    if r.status_code != 200:
        print("❌ Failed to fetch nameservers (HTTP error).")
        print(f"   HTTP Code: {r.status_code}\n")
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

# ═════════════════════════════════════════
# SSL/TLS Mode Manager (Option 7)
# ═════════════════════════════════════════

def ssl_tls_mode_manager(session, zone_id):
    print("\n🔐 Checking current SSL/TLS Mode...")
    spin_stop = spinner_start("🔍 Fetching SSL mode")
    r = session.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl")
    spin_stop()

    if r.status_code == 403:
        print("⚠ Missing Zone Settings:Edit permission. Please recreate token.\n")
        input("Press Enter to return...")
        return
    if r.status_code != 200:
        print("❌ Failed to fetch SSL mode (HTTP error).")
        print(f"   HTTP Code: {r.status_code}\n")
        input("Press Enter to return...")
        return

    data = r.json()
    if not data.get("success"):
        print("❌ Failed to fetch SSL mode (API error).\n")
        input("Press Enter to return...")
        return

    current_mode = data["result"]["value"].capitalize()
    print(f"🌐 Current SSL/TLS Mode: {current_mode}\n")

    print("Available Modes:")
    print(" 1) Flexible")
    print(" 2) Full")
    print(" 3) Strict\n")
    choice = input("Select new mode (1-3) or Enter to skip: ").strip()

    mode_map = {"1": "flexible", "2": "full", "3": "strict"}
    if choice not in mode_map:
        print("⚠ No change applied.\n")
        input("Press Enter to return...")
        return

    new_mode = mode_map[choice]
    print(f"🔄 Updating to {new_mode.capitalize()}...")
    spin_stop = spinner_start("⚙️ Applying")
    r2 = session.patch(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl",
        headers=session.headers,
        json={"value": new_mode}
    )
    spin_stop()

    if r2.status_code == 403:
        print("⚠ Missing Zone Settings:Edit permission. Cannot update SSL mode.\n")
    elif r2.status_code == 200 and r2.json().get("success"):
        print(f"✅ SSL/TLS mode changed to {new_mode.capitalize()}.\n")
    else:
        print("❌ Failed to update SSL mode.\n")

    input("Press Enter to return to main menu...")

# ═════════════════════════════════════════
# Tools Menu (Option 8)
# ═════════════════════════════════════════

def tools_menu(session, zone_id, domain, token):
    while True:
        print("\n🛠 Tools Menu")
        print("━━━━━━━━━━━━━━━━━━━")
        print("[1] Add Specific Domain")
        print("[2] Remove Specific Domain")
        print("[3] Abuse Check")
        print("[4] Check Token Permissions")
        print("[5] Show All Domains")
        print("━━━━━━━━━━━━━━━━━━━")

        c = input("Choose: ").strip()

        if c == "1":
            new_dom = input("Enter domain to add: ").strip()
            if not new_dom:
                print("❌ No domain.\n")
                continue
            add_specific_domain(session, new_dom)

        elif c == "2":
            remove_specific_domain(session)

        elif c == "3":
            spin_stop = spinner_start("🔍 Scanning for Abuse / Suspension")
            status_flag = get_zone_status(session, zone_id)
            spin_stop()
            if status_flag == 0:
                print("✅ Clean. No abuse/suspension detected.\n")
            else:
                print("⚠️ Possible suspension / hold detected.\n")

        elif c == "4":
            check_token_permissions_display(token)

        elif c == "5":
            show_all_domains(session)

        else:
            # any other key => back
            break

# ═════════════════════════════════════════
# Main Menu
# ═════════════════════════════════════════

def main_menu_loop(session, token, zone_id, domain):
    while True:
        abuse_flag = get_zone_status(session, zone_id)
        total_dns  = len(list_dns(session, zone_id))

        print("\n╭────────────────────────────────────────────╮")
        print("│ Cloudflare DNS Manager v9.7.5 — MHR Edition │")
        print("│    Developed by MHR Dev Team 🌿             │")
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
            show_nameservers(session, zone_id)
        elif choice == "7":
            ssl_tls_mode_manager(session, zone_id)
        elif choice == "8":
            tools_menu(session, zone_id, domain, token)
        elif choice == "9":
            delete_credentials()
            break
        elif choice == "10":
            print("👋 Exiting...")
            time.sleep(0.4)
            break
        else:
            print("❌ Invalid option.\n")

# ═════════════════════════════════════════
# Entry point (with --check-token mode + Permission Guard)
# ═════════════════════════════════════════

def main():
    # quick mode: just check token
    if len(sys.argv) > 1 and sys.argv[1] == "--check-token":
        token = getpass.getpass("Enter Cloudflare API Token: ").strip()
        check_token_permissions_display(token)
        return

    # normal mode
    creds = load_credentials()
    if creds:
        token, zone_id, domain = creds["token"], creds["zone_id"], creds["domain"]
    else:
        token, zone_id, domain = get_auth()

    # make session
    session = requests.Session()
    session.headers.update(cf_headers(token))

    # 🔐 Permission Guard before menu:
    permission_guard(token)

    # then show menu loop
    main_menu_loop(session, token, zone_id, domain)

if __name__ == "__main__":
    main()
