#!/usr/bin/env python3
# ═════════════════════════════════════════════════════════════
#  Cloudflare DNS Manager v10 GLOBAL FLOW
#  Made by MHR 🌿  |  MHR Dev Team
#
#  1-Click Flow:
#   - You run script
#   - Script asks only for your Cloudflare Global API Key
#   - Script creates an internal full-permission scoped token
#   - Script lists all your domains (zones)
#   - You pick which domain to manage (1/2/3...)
#   - Then full panel opens: DNS create/list/delete, SSL/TLS, Tools, etc.
#
#  No manual token / no zone_id / no domain typing needed.
#
#  Security:
#   • Global API Key is never saved to disk.
#   • We do NOT write credentials.json here.
#     (So every run, you'll paste Global API Key fresh)
#   • We create a temporary scoped token via API and use that in-memory.
#
#  Requirements (Debian/Ubuntu fresh VPS):
#     apt update -y && apt install -y python3 python3-pip
#     pip3 install requests
#
#  Run:
#     python3 cf_auto_dns_v10_global_flow.py
#
# ═════════════════════════════════════════════════════════════

import requests, json, os, sys, time, getpass, random, string, re, itertools, threading
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
    """
    Compact single-line progress bar.
    Example:
    ⚙️ Creating (3/10) |██████░░░░░░| 60%
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

# ═══════════════════════════════════════
# Helper utils
# ═══════════════════════════════════════

def natural_sort_key(name: str):
    """
    So that us1, us2, us10 sorts like 1,2,10 not 1,10,2.
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

def cf_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }

# ═══════════════════════════════════════
# Cloudflare auth via Global API Key
# ═══════════════════════════════════════

def create_scoped_token_with_global(global_api_key):
    """
    Use Cloudflare Global API Key to create a new scoped token with
    full DNS / Zone / SSL permissions.
    Returns token string on success, else None.

    NOTE:
    - The Global API Key here is assumed to be valid master access.
    - We do not store global_api_key to disk.
    """
    url = "https://api.cloudflare.com/client/v4/user/tokens"

    template = {
      "name": "Full Access Token – MHR Script (ephemeral)",
      "policies": [
        {
          "effect": "allow",
          "resources": [
            "com.cloudflare.api.account.*",
            "com.cloudflare.api.user.*",
            "com.cloudflare.api.zone.*"
          ],
          "permission_groups": [
            {"id": "Zone.Zone"},
            {"id": "Zone.Zone.Edit"},
            {"id": "Zone.ZoneSettings.Read"},
            {"id": "Zone.ZoneSettings.Edit"},
            {"id": "Zone.DNS.Read"},
            {"id": "Zone.DNS.Edit"},
            {"id": "Zone.SSLandCertificates.Edit"},
            {"id": "User.UserDetails.Read"}
          ]
        }
      ]
    }

    headers = {
        "Authorization": f"Bearer {global_api_key}",
        "Content-Type": "application/json"
    }

    stop = spinner_start("🔐 Creating scoped token from Global API Key")
    try:
        r = requests.post(url, headers=headers, json=template, timeout=30)
    finally:
        stop()

    if r.status_code != 200:
        print(f"\n❌ Failed to create scoped token (HTTP {r.status_code})")
        try:
            print(r.text)
        except:
            pass
        return None

    body = r.json()
    if not body.get("success"):
        print("\n❌ Cloudflare returned error creating token:")
        print(body)
        return None

    token_value = body["result"].get("value")
    if not token_value:
        print("\n❌ No token value returned.")
        return None

    print("✅ Scoped token created.\n")
    return token_value

def get_all_zones(scoped_token):
    """
    Return list of zones as list[ {id,name,status} ]
    """
    session = requests.Session()
    session.headers.update(cf_headers(scoped_token))

    stop = spinner_start("🌍 Fetching your domains from Cloudflare")
    r = session.get("https://api.cloudflare.com/client/v4/zones")
    stop()

    if r.status_code != 200:
        print(f"\n❌ Failed to list zones (HTTP {r.status_code})")
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
    """
    Show zones with index so user can pick.
    Returns (zone_id, zone_name) or (None,None)
    """
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
        zid    = chosen["id"]
        dname  = chosen["name"]
        return zid, dname

def login_global_flow():
    """
    1) Ask user for Global API Key
    2) Create internal scoped token
    3) List all zones -> user picks one
    4) Return (scoped_token, zone_id, domain)
    """
    print("🔑 Cloudflare Global Login")
    print("   Enter your Global API Key (Master Key)")
    print("   (We will NOT save it to disk.)\n")
    global_api_key = getpass.getpass("Global API Key: ").strip()
    if not global_api_key:
        print("❌ No Global API Key provided. Exiting.")
        sys.exit(1)

    scoped_token = create_scoped_token_with_global(global_api_key)
    if not scoped_token:
        print("❌ Could not create scoped token. Exiting.")
        sys.exit(1)

    # Now using the scoped token (safer than global key)
    zones = get_all_zones(scoped_token)
    if zones is None:
        print("❌ Could not retrieve domains from account. Exiting.")
        sys.exit(1)

    zid, dom = pick_zone_interactive(zones)
    if not zid or not dom:
        print("❌ No domain selected. Exiting.")
        sys.exit(1)

    # best-effort: forget the global key now
    global_api_key = None

    print(f"\n✅ Selected domain: {dom}")
    print(f"   Zone ID        : {zid}\n")

    return scoped_token, zid, dom

# ═══════════════════════════════════════
# CF basic helpers
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
    data = r.json()
    return data.get("result", [])

def get_zone_status(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    if r.status_code == 200:
        status = r.json().get("result", {}).get("status", "")
        if status in ["suspended", "locked", "hold"]:
            return 1
        return 0
    return 0

# ═══════════════════════════════════════
# Permission guard / token check
# ═══════════════════════════════════════

def check_token_permissions_raw(token):
    """
    Ask Cloudflare what perms this token has.
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
            nm = perm.get("name")
            if nm:
                perms_list.append(nm)
    return True, 200, perms_list

def check_token_permissions_display(token):
    """
    Tools → Check Token Permissions
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
    Warn user if critical perms might be missing.
    """
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

    perms_list = payload
    blob = " | ".join(perms_list)

    normalized_reqs = [
        ("Zone Read", ["Zone Read"]),
        ("Zone Edit", ["Zone Edit"]),
        ("Zone Settings Read", ["Zone Settings Read","Zone Settings:Read"]),
        ("Zone Settings Edit", ["Zone Settings Edit","Zone Settings:Edit"]),
        ("DNS Read", ["DNS Read","Zone DNS Read"]),
        ("DNS Edit", ["DNS Edit","Zone DNS Edit"]),
        ("SSL and Certificates Edit", ["SSL and Certificates Edit","SSL Edit","SSL and Certificates:Edit"]),
        ("User Read", ["User Read","User Details Read","User Details:Read",
                       "User Details Read permission"]),
    ]

    missing_any = False
    missing_list = []
    for human_name, patterns in normalized_reqs:
        found = any(pat.lower() in blob.lower() for pat in patterns)
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

        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
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

        if resp.status_code == 200 and resp.json().get("success"):
            print(f"\n✅ {sub} → {ip} created successfully.")
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
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

# ═══════════════════════════════════════
# DNS List (Normal View)
# ═══════════════════════════════════════

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

# ═══════════════════════════════════════
# DNS List (Pro View)
# ═══════════════════════════════════════

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

# ═══════════════════════════════════════
# Name Server Manager (View current CF nameservers)
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

# ═══════════════════════════════════════
# SSL/TLS Mode Manager
# ═══════════════════════════════════════

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

# ═══════════════════════════════════════
# Tools Menu
# ═══════════════════════════════════════

def list_all_domains(session):
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

def add_specific_domain(session):
    """
    Cloudflare requires adding root domains, not subdomains.
    """
    new_domain = input("Enter domain to add (root only, e.g. example.com): ").strip()
    if not new_domain:
        print("❌ No domain.\n")
        return
    # basic sanity:
    if new_domain.count(".") < 1:
        print("❌ Invalid domain format.\n")
        return
    if new_domain.count(".") >= 2:
        print("⚠ That looks like a subdomain. You can't add subdomain as a new zone.\n")
        return

    stop = spinner_start("🧩 Adding Domain to Cloudflare")
    resp = cf_post(
        session,
        "https://api.cloudflare.com/client/v4/zones",
        {"name": new_domain, "jump_start": True}
    )
    stop()

    if resp.status_code == 200 and resp.json().get("success"):
        result  = resp.json().get("result", {})
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
        try:
            print(resp.text + "\n")
        except:
            pass

def remove_specific_domain(session):
    """
    Choose zone to delete from account entirely.
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

def tools_menu(session, zone_id, domain, token):
    while True:
        print("\n🛠 Tools Menu")
        print("━━━━━━━━━━━━━━━━━━━")
        print("[1] Add Domain to Cloudflare")
        print("[2] Remove Domain from Cloudflare")
        print("[3] Abuse Check for Current Domain")
        print("[4] Check Token Permissions")
        print("[5] Show All Domains")
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
            check_token_permissions_display(token)
        elif c == "5":
            show_all_domains(session)
        else:
            break

# ═══════════════════════════════════════
# Main menu loop
# ═══════════════════════════════════════

def main_menu_loop(session, token, zone_id, domain):
    while True:
        abuse_flag = get_zone_status(session, zone_id)
        total_dns  = len(list_dns(session, zone_id))

        print("\n╭────────────────────────────────────────────╮")
        print("│ Cloudflare DNS Manager v10 (GLOBAL FLOW)   │")
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
            tools_menu(session, zone_id, domain, token)
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
    # STEP 1: ask for global API key, create scoped token, choose zone
    token, zone_id, domain = login_global_flow()

    # STEP 2: build session for all other requests
    session = requests.Session()
    session.headers.update(cf_headers(token))

    # STEP 3: permission guard (warn if perms missing)
    permission_guard(token)

    # STEP 4: main control menu
    main_menu_loop(session, token, zone_id, domain)

if __name__ == "__main__":
    main()
