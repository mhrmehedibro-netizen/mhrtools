#!/usr/bin/env python3
# ═════════════════════════════════════════════════════════════
#  Cloudflare DNS Manager v11 GLOBAL EMAIL+KEY MODE
#  Made by MHR 🌿  |  MHR Dev Team
#
#  Flow:
#   - Run script
#   - Script asks:
#        Cloudflare Email (visible)
#        Global API Key  (visible)
#   - Script uses those to talk DIRECT to Cloudflare (X-Auth-Email / X-Auth-Key)
#   - Script lists ALL zones (domains) in your account
#   - You pick which domain (1/2/3...)
#   - Then full control panel opens:
#        DNS create / random create / delete / list / SSL-TLS / Nameserver / Tools
#
#  No manual zone_id typing
#  No manual token typing
#  No saving creds to disk
#
#  Requirements (fresh Debian VPS):
#     apt update -y && apt install -y python3 python3-pip
#     pip3 install requests
#
#  Run:
#     python3 cf_auto_dns_v11_global_emailkey.py
#
#  ⚠ SECURITY NOTE:
#    This script shows your email + global key in terminal (your request).
#    Do not share screen / do not run on shared VPS.
#
# ═════════════════════════════════════════════════════════════

import requests, json, sys, time, random, string, re, itertools, threading
from datetime import datetime

DIV = "────────────────────────────────────────────"

FLAG_MAP = {
    "us": "🇺🇸",
    "uk": "🇬🇧",
    "ca": "🇨🇦",
    "de": "🇩🇪",
    "fr": "🇫🇷",
    "jp": "🇯🇵",
    "in": "🇮🇳",
}

# ═══════════════════════════════════════
# Spinner + Progress visuals
# ═══════════════════════════════════════

def spinner_start(text="Processing"):
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
    width  = 12
    ratio  = (current / total) if total else 1
    filled = int(ratio * width)
    bar    = "█" * filled + "░" * (width - filled)
    pct    = int(ratio * 100)
    sys.stdout.write(f"\r{prefix} ({current}/{total}) |{bar}| {pct}%")
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")

# ═══════════════════════════════════════
# Helper utils
# ═══════════════════════════════════════

def natural_sort_key(name: str):
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

def cf_headers(email, global_key):
    return {
        "X-Auth-Email": email,
        "X-Auth-Key":   global_key,
        "Content-Type": "application/json"
    }

# ═══════════════════════════════════════
# Cloudflare Global API login flow
# ═══════════════════════════════════════

def get_all_zones(session):
    stop = spinner_start("🌍 Fetching your domains from Cloudflare")
    r = session.get("https://api.cloudflare.com/client/v4/zones")
    stop()

    if r.status_code != 200:
        print(f"\n❌ Failed to list zones (HTTP {r.status_code})")
        try:
            print(r.text)
        except:
            pass
        return None
    data = r.json()
    if not data.get("success"):
        print("\n❌ API returned error while listing zones.")
        return None

    zones = data.get("result", [])
    out = []
    for z in zones:
        out.append({
            "id": z.get("id", ""),
            "name": z.get("name", ""),
            "status": z.get("status", "")
        })
    return out

def pick_zone_interactive(zones):
    if not zones:
        print("⚠ No domains found in your account.")
        return None, None

    print("\n🌐 Available Domains (Zones):")
    print(DIV)
    for i, z in enumerate(zones, start=1):
        print(f"{i}) {z['name']}   → {z['status']}   [zone_id={z['id']}]")
    print(DIV)

    while True:
        pick = input("Select domain number to manage: ").strip()
        if not pick.isdigit():
            print("❌ Invalid. Please enter a number from the list.")
            continue
        idx = int(pick)
        if idx < 1 or idx > len(zones):
            print("❌ Out of range.")
            continue
        chosen = zones[idx - 1]
        return chosen["id"], chosen["name"]

def login_global_flow():
    print("🔑 Cloudflare Global Login (Email + Global API Key)")
    print("   We won't save these. Visible input (your request).")
    print("   Make sure nobody is screen-sharing now.\n")

    email = input("Enter your Cloudflare Email: ").strip()
    if not email:
        print("❌ No email provided. Exiting.")
        sys.exit(1)

    global_key = input("Enter your Global API Key: ").strip()
    if not global_key:
        print("❌ No Global API Key provided. Exiting.")
        sys.exit(1)

    # build session with these headers
    session = requests.Session()
    session.headers.update(cf_headers(email, global_key))

    # list zones
    zones = get_all_zones(session)
    if zones is None:
        print("❌ Could not retrieve domains from account. Exiting.")
        sys.exit(1)

    zone_id, domain = pick_zone_interactive(zones)
    if not zone_id or not domain:
        print("❌ No domain selected. Exiting.")
        sys.exit(1)

    print(f"\n✅ Selected domain: {domain}")
    print(f"   Zone ID        : {zone_id}\n")

    return session, zone_id, domain

# ═══════════════════════════════════════
# CF basic helpers using session (global headers)
# ═══════════════════════════════════════

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
    try:
        data = r.json()
    except Exception:
        return []
    return data.get("result", [])

def get_zone_status(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    if r.status_code == 200:
        result = r.json().get("result", {})
        status = result.get("status", "")
        if status in ["suspended", "locked", "hold"]:
            return 1
        return 0
    return 0

# ═══════════════════════════════════════
# Permission guard replacement
# (global key doesn't support /user/tokens/verify like bearer tokens)
# We'll just do a soft warning + basic test write like DNS create dry-run?
# We'll keep it simple: just warn.
# ═══════════════════════════════════════

def permission_guard_soft():
    print("\n🔍 Permission Note")
    print("   Using Global API Key gives full account access (God Mode).")
    print("   We will NOT verify granular scopes like token verify.")
    ans = input("Continue with full-access Global Key? (y/n): ").strip().lower()
    if ans != "y":
        print("👋 Exiting.")
        sys.exit(1)
    print("✅ Continuing with Global Key.\n")

# ═══════════════════════════════════════
# DNS Create (sequential prefix: us1, us2...)
# ═══════════════════════════════════════

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

        if resp.status_code == 200:
            body = {}
            try:
                body = resp.json()
            except:
                pass
            if body.get("success"):
                print(f"\n✅ {sub} → {ip} created successfully.")
            else:
                print(f"\n❌ Failed: {sub} → {ip}")
                print(body)
        else:
            print(f"\n❌ HTTP {resp.status_code} for {sub} → {ip}")
            try:
                print(resp.text)
            except:
                pass

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# ═══════════════════════════════════════
# DNS Create (random subdomain)
# ═══════════════════════════════════════

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

        if resp.status_code == 200:
            body = {}
            try:
                body = resp.json()
            except:
                pass
            if body.get("success"):
                print(f"\n✅ {sub} → {ip} created successfully.")
            else:
                print(f"\n❌ Failed: {sub} → {ip}")
                print(body)
        else:
            print(f"\n❌ HTTP {resp.status_code} for {sub} → {ip}")
            try:
                print(resp.text)
            except:
                pass

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s\n")

# ═══════════════════════════════════════
# DNS Delete
# ═══════════════════════════════════════

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
        spin_stop()

        results = []
        try:
            results = r.json().get("result", [])
        except:
            pass

        if not results:
            print("❌ Not found.\n")
            return

        rid = results[0]["id"]
        d   = cf_delete(
            session,
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}"
        )

        if d.status_code == 200:
            body = {}
            try:
                body = d.json()
            except:
                pass
            if body.get("success"):
                print(f"🗑️ Deleted: {name}\n")
            else:
                print("❌ Delete failed.\n")
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

# ═══════════════════════════════════════
# DNS List (Normal View)
# ═══════════════════════════════════════

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

# ═══════════════════════════════════════
# DNS List (Pro View)
# ═══════════════════════════════════════

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

# ═══════════════════════════════════════
# Name Server Manager
# ═══════════════════════════════════════

def show_nameservers(session, zone_id):
    print("\n🔍 Fetching Cloudflare Nameservers...")
    stop = spinner_start("📡 Getting nameservers")
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    stop()

    if r.status_code != 200:
        print("❌ Failed to fetch nameservers (HTTP error).")
        print(f"   HTTP Code: {r.status_code}\n")
        input("Press Enter to return...")
        return

    data = {}
    try:
        data = r.json()
    except:
        pass

    if not data.get("success"):
        print("❌ Failed to fetch nameservers (API error).\n")
        input("Press Enter to return...")
        return

    ns_list = data.get("result", {}).get("name_servers", [])
    if not ns_list:
        print("⚠ No nameservers found (zone may not be active yet).\n")
        input("Press Enter to return...")
        return

    print("\n📡 Current Cloudflare Nameservers:")
    for i, ns in enumerate(ns_list, start=1):
        print(f" {i}. {ns}")
    print("\n✅ Nameservers fetched successfully!\n")
    input("Press Enter to return to main menu...")

# ═══════════════════════════════════════
# SSL/TLS Mode Manager
# ═══════════════════════════════════════

def ssl_tls_mode_manager(session, zone_id):
    print("\n🔐 Checking current SSL/TLS Mode...")
    stop = spinner_start("🔍 Fetching SSL mode")
    r = session.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl")
    stop()

    if r.status_code == 403:
        print("⚠ Missing permission to edit SSL/TLS.\n")
        input("Press Enter to return...")
        return
    if r.status_code != 200:
        print("❌ Failed to fetch SSL mode (HTTP error).")
        print(f"   HTTP Code: {r.status_code}\n")
        input("Press Enter to return...")
        return

    data = {}
    try:
        data = r.json()
    except:
        pass

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
    stop2 = spinner_start("⚙️ Applying")
    r2 = session.patch(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl",
        json={"value": new_mode}
    )
    stop2()

    if r2.status_code == 403:
        print("⚠ Missing permission. Cannot update SSL mode.\n")
    elif r2.status_code == 200:
        body2 = {}
        try:
            body2 = r2.json()
        except:
            pass

        if body2.get("success"):
            print(f"✅ SSL/TLS mode changed to {new_mode.capitalize()}.\n")
        else:
            print("❌ Failed to update SSL mode.\n")
    else:
        print("❌ Failed to update SSL mode.\n")

    input("Press Enter to return to main menu...")

# ═══════════════════════════════════════
# Tools Menu
# ═══════════════════════════════════════

def list_all_domains(session):
    r = cf_get(session, "https://api.cloudflare.com/client/v4/zones")
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"
    body = {}
    try:
        body = r.json()
    except:
        pass
    if not body.get("success"):
        return None, "API error"
    zones = body.get("result", [])
    out = []
    for z in zones:
        out.append({
            "id": z.get("id", ""),
            "name": z.get("name", ""),
            "status": z.get("status", "")
        })
    return out, None

def add_specific_domain(session):
    new_domain = input("Enter domain to add (root only, e.g. example.com): ").strip()
    if not new_domain:
        print("❌ No domain.\n")
        return
    if new_domain.count(".") < 1:
        print("❌ Invalid domain format.\n")
        return
    if new_domain.count(".") >= 2:
        print("⚠ Looks like subdomain. You can't add subdomain as a new zone.\n")
        return

    stop = spinner_start("🧩 Adding Domain to Cloudflare")
    resp = cf_post(
        session,
        "https://api.cloudflare.com/client/v4/zones",
        {"name": new_domain, "jump_start": True}
    )
    stop()

    if resp.status_code == 200:
        body = {}
        try:
            body = resp.json()
        except:
            pass
        if body.get("success"):
            result  = body.get("result", {})
            zid     = result.get("id")
            status  = result.get("status")
            print("✅ Domain added.")
            print("   Domain :", new_domain)
            print("   Zone ID:", zid)
            print("   Status :", status, "\n")
            with open("domain_activity_log.txt", "a") as f:
                f.write(f"[{datetime.utcnow().isoformat()}] ADDED {new_domain} zone_id={zid} status={status}\n")
        else:
            print("❌ Failed to add domain.\n")
            print(body)
    else:
        print("❌ Failed to add domain.\n")
        try:
            print(resp.text + "\n")
        except:
            pass

def remove_specific_domain(session):
    zones, err = list_all_domains(session)
    if err or zones is None:
        print(f"❌ Could not list domains ({err}).\n")
        return
    if not zones:
        print("⚠ No domains found on this account.\n")
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

    if resp.status_code == 200:
        body = {}
        try:
            body = resp.json()
        except:
            pass
        if body.get("success"):
            print(f"🗑️ Domain removed: {dom} (zone_id={zid})\n")
            with open("domain_activity_log.txt", "a") as f:
                f.write(f"[{datetime.utcnow().isoformat()}] REMOVED {dom} zone_id={zid}\n")
        else:
            print("❌ Failed to remove domain.\n")
            print(body)
    else:
        print("❌ Failed to remove domain.\n")
        try:
            print(resp.text + "\n")
        except:
            pass

def show_all_domains(session):
    zones, err = list_all_domains(session)
    if err or zones is None:
        print(f"❌ Could not list domains ({err}).\n")
        return
    if not zones:
        print("⚠ No domains found.\n")
        return

    print(f"\n🌐 Total Domains: {len(zones)}")
    print("────────────────────────────")
    lines = []
    for i, z in enumerate(zones, start=1):
        line = f"{i}) {z['name']}  → {z['status']}  [zone_id={z['id']}]"
        print(line)
        lines.append(line)
    print("────────────────────────────\n")

    with open("domain_list.txt", "w") as f:
        for L in lines:
            f.write(L + "\n")
    print("📄 Saved to domain_list.txt\n")

def tools_menu(session, zone_id, domain):
    while True:
        print("\n🛠 Tools Menu")
        print("━━━━━━━━━━━━━━━━━━━")
        print("[1] Add Domain to Cloudflare")
        print("[2] Remove Domain from Cloudflare")
        print("[3] Abuse Check for Current Domain")
        print("[4] Show All Domains")
        print("[0] Back")
        print("━━━━━━━━━━━━━━━━━━━")

        c = input("Choose: ").strip()

        if c == "1":
            add_specific_domain(session)
        elif c == "2":
            remove_specific_domain(session)
        elif c == "3":
            stop = spinner_start("🔍 Checking for suspend/abuse status")
            status_flag = get_zone_status(session, zone_id)
            stop()
            if status_flag == 0:
                print("✅ Clean. No abuse/suspension detected.\n")
            else:
                print("⚠️ Possible suspension / hold detected.\n")
        elif c == "4":
            show_all_domains(session)
        else:
            break

# ═══════════════════════════════════════
# Main menu loop
# ═══════════════════════════════════════

def main_menu_loop(session, zone_id, domain):
    while True:
        abuse_flag = get_zone_status(session, zone_id)
        total_dns  = len(list_dns(session, zone_id))

        print("\n╭────────────────────────────────────────────╮")
        print("│ Cloudflare DNS Manager v11 (GLOBAL MODE)   │")
        print("│        Developed by MHR Dev Team 🌿        │")
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
        print(" [9] Exit")
        print(DIV)

        choice = input(" Select Option (1-9): ").strip()

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
            print("👋 Exiting...")
            time.sleep(0.4)
            break
        else:
            print("❌ Invalid option.\n")

# ═══════════════════════════════════════
# Entry point
# ═══════════════════════════════════════

def main():
    # 1) Ask for e-mail + global key (visible)
    session, zone_id, domain = login_global_flow()

    # 2) Warn about god mode perms
    permission_guard_soft()

    # 3) Show main menu
    main_menu_loop(session, zone_id, domain)

if __name__ == "__main__":
    import time, sys
    main()
