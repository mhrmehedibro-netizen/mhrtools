#!/usr/bin/env python3
# Cloudflare DNS Manager v10.2 (GLOBAL)
# Developed by MHR Dev Team 🌿
#
# Flow:
#  - Ask Cloudflare Email + Global API Key (or load saved from /root/.cf_global_auth)
#  - Use Global API Key to mint a scoped token with full DNS/Zone/SSL perms
#  - List all zones, let user pick one
#  - Show main menu:
#       Create DNS, Random DNS, Delete DNS, List DNS, Nameserver, SSL/TLS, Tools, Logout, Exit
#
# Security:
#   - We store creds only if user says "y" when prompted.
#   - Logout (option [0]) deletes /root/.cf_global_auth and exits.
#
# Requirements:
#   apt update -y && apt install -y python3 python3-pip jq
#   pip3 install requests
#
# Run:
#   python3 /root/cf_auto_dns_v10_2_full.py
#

import requests, json, os, sys, time, getpass, random, string, re, itertools, threading
from datetime import datetime

AUTH_FILE = "/root/.cf_global_auth"
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

# ─────────────────────────────────────────
# Spinner + Progress visuals
# ─────────────────────────────────────────

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

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def natural_sort_key(name: str):
    # ensures us1, us2, us10 sorts as 1,2,10
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(r'([0-9]+)', name)]

def timed_input_list(prompt="Paste IPs (one per line). Press Enter twice to finish:"):
    print(prompt)
    lines = []
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
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

# ─────────────────────────────────────────
# Auth storage/load
# ─────────────────────────────────────────

def save_auth(email, global_key):
    try:
        with open(AUTH_FILE, "w") as f:
            f.write(json.dumps({
                "email": email,
                "global_api_key": global_key
            }))
        os.chmod(AUTH_FILE, 0o600)
        print("💾 Credentials saved.")
    except Exception as e:
        print(f"⚠️ Could not save credentials: {e}")

def load_auth():
    if not os.path.exists(AUTH_FILE):
        return None, None
    try:
        with open(AUTH_FILE, "r") as f:
            data = json.loads(f.read().strip())
        return data.get("email",""), data.get("global_api_key","")
    except:
        return None, None

def clear_auth():
    if os.path.exists(AUTH_FILE):
        os.remove(AUTH_FILE)

# ─────────────────────────────────────────
# Cloudflare auth via Global API Key -> create scoped token
# ─────────────────────────────────────────

def create_scoped_token_with_global(email, global_api_key):
    """
    Uses Global API Key + email to hit Cloudflare and mint a scoped bearer token.
    We'll emulate the "Authorization: Bearer <global>" behavior from previous steps,
    but many Cloudflare endpoints actually expect "X-Auth-Email / X-Auth-Key" for global key usage.
    So we'll try token create with that header style.
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

    # For global API key auth:
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": global_api_key,
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
    # try load
    saved_email, saved_key = load_auth()

    print("🔑 Cloudflare Global Login (v10.2 GLOBAL)")
    if saved_email and saved_key:
        print("ℹ Using saved credentials.")
        email = saved_email
        global_api_key = saved_key
        ask_save = None  # already saved
    else:
        email = input("Enter your Cloudflare Email: ").strip()
        global_api_key = getpass.getpass("Enter your Global API Key: ").strip()

        if not email or not global_api_key:
            print("❌ Missing email or global API key. Exiting.")
            sys.exit(1)

        ask_save = input("Save credentials for next time? [y/N]: ").strip().lower()
        if ask_save == "y":
            save_auth(email, global_api_key)

    scoped_token = create_scoped_token_with_global(email, global_api_key)
    if not scoped_token:
        print("❌ Could not create scoped token. Exiting.")
        sys.exit(1)

    zones = get_all_zones(scoped_token)
    if zones is None:
        print("❌ Could not retrieve domains from account. Exiting.")
        sys.exit(1)

    zid, dom = pick_zone_interactive(zones)
    if not zid or not dom:
        print("❌ No domain selected. Exiting.")
        sys.exit(1)

    print(f"\n✅ Selected domain: {dom}")
    print(f"   Zone ID        : {zid}\n")

    # we don't store global key again here
    return scoped_token, zid, dom

# ─────────────────────────────────────────
# Cloudflare basic helpers
# ─────────────────────────────────────────

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

def get_zone_status_raw(session, zone_id):
    r = cf_get(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}")
    if r.status_code == 200:
        return r.json().get("result", {}).get("status", "")
    return "unknown"

def zone_status_display(zone_status_raw):
    s = (zone_status_raw or "").lower()
    if "suspend" in s or "hold" in s or "lock" in s:
        return "Suspended ⚠️"
    if "active" in s:
        return "Active ✔️"
    if "pending" in s:
        return "Pending ❓"
    return "Unknown ❓"

# ─────────────────────────────────────────
# DNS Create (sequential prefix: us1, us2...)
# ─────────────────────────────────────────

def create_dns_records(session, zone_id, domain):
    base = input("\nBase name (us/uk/ca/custom): ").strip().lower()
    ips  = timed_input_list("Paste IPs (one per line). Press Enter twice to finish:")
    if not ips:
        print("❌ No IPs provided. Cancelled.\n")
        return

    start_t = time.perf_counter()
    total   = len(ips)
    print("\n⚙️ Creating DNS Records...\n")

    # We'll also collect per-group for txt export
    created_pairs = []  # (subdomain, ip)

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
            created_pairs.append((sub, ip))
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            try:
                print(resp.text)
            except:
                pass

    # write grouped txt file
    # group by prefix letters before number (e.g. "us1" -> "us")
    groups = {}
    for sub, ip in created_pairs:
        first_label = sub.split(".")[0]
        m = re.match(r"^([a-zA-Z]+)", first_label)
        prefix = m.group(1).lower() if m else "other"
        groups.setdefault(prefix, []).append((sub, ip))

    ts_name = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_fname = f"dns_created_{ts_name}.txt"
    with open(out_fname, "w") as outf:
        for prefix, items in groups.items():
            # sort by natural order (us1,us2,...)
            items_sorted = sorted(items, key=lambda x: natural_sort_key(x[0]))
            # compact join of just the subdomains with ~
            just_names = [a for (a, _) in items_sorted]
            joined = "~".join(just_names)
            flag = FLAG_MAP.get(prefix.lower(), "🏳️")
            outf.write(f"{flag} {prefix.upper()}\n")
            outf.write(joined + "\n\n")

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s")
    print(f"📝 Saved grouped list to {out_fname}\n")
    # future: SMTP/WhatsApp send could attach out_fname

# ─────────────────────────────────────────
# DNS Create (random subdomain)
# ─────────────────────────────────────────

def create_dns_random(session, zone_id, domain):
    ips = timed_input_list("Paste IPs (one per line). Press Enter twice to finish:")
    if not ips:
        print("❌ No IPs provided. Cancelled.\n")
        return

    start_t = time.perf_counter()
    total   = len(ips)
    print("\n⚙️ Creating DNS Records (Random)...\n")

    created_pairs = []

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
            created_pairs.append((sub, ip))
        else:
            print(f"\n❌ Failed: {sub} → {ip}")
            try:
                print(resp.text)
            except:
                pass

    # grouped txt (random prefixes will vary)
    groups = {}
    for sub, ip in created_pairs:
        first_label = sub.split(".")[0]
        m = re.match(r"^([a-zA-Z]+)", first_label)
        prefix = m.group(1).lower() if m else "other"
        groups.setdefault(prefix, []).append((sub, ip))

    ts_name = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_fname = f"dns_created_random_{ts_name}.txt"
    with open(out_fname, "w") as outf:
        for prefix, items in groups.items():
            items_sorted = sorted(items, key=lambda x: natural_sort_key(x[0]))
            just_names = [a for (a, _) in items_sorted]
            joined = "~".join(just_names)
            flag = FLAG_MAP.get(prefix.lower(), "🏳️")
            outf.write(f"{flag} {prefix.upper()}\n")
            outf.write(joined + "\n\n")

    total_time = time.perf_counter() - start_t
    print(f"\n✔ Done. Total Created: {total}")
    print(f"⏱ Time: {total_time:.2f}s")
    print(f"📝 Saved grouped list to {out_fname}\n")

# ─────────────────────────────────────────
# DNS Delete
# 1) delete single record by full name
# 2) delete by prefix group (us / uk / etc)
# 3) delete ALL (one confirm)
# ─────────────────────────────────────────

def delete_dns(session, zone_id):
    print("\n🧹 DNS Delete Menu")
    print("1) Delete by Full Record Name")
    print("2) Delete by Group Prefix (e.g. 'us' deletes us1/us2/...)")
    print("3) Delete ALL Records")
    print("4) Back")
    choice = input("Choose: ").strip()

    # 1) Delete by full name
    if choice == "1":
        name = input("Enter full DNS name to delete (e.g. us1.example.com): ").strip()
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

    # 2) Delete by prefix group
    if choice == "2":
        group_prefix = input("Enter group prefix (e.g. 'us'): ").strip().lower()
        if not group_prefix:
            print("❌ No prefix.\n")
            return

        # get all records
        recs = list_dns(session, zone_id)
        # find matches like us1.example.com, us2.example.com...
        targets = []
        for rec in recs:
            full = rec.get("name","")
            first_label = full.split(".")[0]
            # extract leading letters = prefix "us", ignore numbers
            m = re.match(r"^([a-zA-Z]+)([0-9]+)$", first_label)
            if not m:
                continue
            prefix_only = m.group(1).lower()
            if prefix_only == group_prefix:
                targets.append((rec["id"], full))

        if not targets:
            print("⚠ No records found for that prefix.\n")
            return

        print(f"⚠ You are about to delete {len(targets)} record(s) with prefix '{group_prefix}'")
        confirm = input("Are you sure? (y/n): ").strip().lower()
        if confirm != "y":
            print("❌ Cancelled.\n")
            return

        start_t = time.perf_counter()
        total = len(targets)
        print(f"\n🧹 Deleting {total} DNS record(s) for group '{group_prefix}'...\n")
        for idx, (rid, fullname) in enumerate(targets, start=1):
            progress_bar(idx, total, prefix="🗑️ Removing")
            cf_delete(session, f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}")
            print(f"\n🗑️ Deleted: {fullname}")
        total_time = time.perf_counter() - start_t
        print(f"\n✅ Total Deleted: {total}")
        print(f"⏱ Time: {total_time:.2f}s\n")
        return

    # 3) Delete ALL Records
    if choice == "3":
        c1 = input("⚠️ Delete ALL DNS records? (y/n): ").lower()
        if c1 != "y":
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

    # 4) Back
    if choice == "4":
        return

# ─────────────────────────────────────────
# DNS List (Normal View)
# ─────────────────────────────────────────

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

# ─────────────────────────────────────────
# DNS List (Pro View)
# ─────────────────────────────────────────

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

# ─────────────────────────────────────────
# Name Server Manager (view only)
# ─────────────────────────────────────────

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

# ─────────────────────────────────────────
# SSL/TLS Mode Manager
# ─────────────────────────────────────────

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

# ─────────────────────────────────────────
# Tools Menu
# ─────────────────────────────────────────

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
    new_domain = input("Enter domain to add (root only, e.g. example.com): ").strip()
    if not new_domain:
        print("❌ No domain.\n")
        return
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
        print("[3] Show All Domains")
        print("[4] Reset SMTP Config (placeholder)")
        print("[0] Back")
        print("━━━━━━━━━━━━━━━━━━━")

        c = input("Choose: ").strip()

        if c == "1":
            add_specific_domain(session)
        elif c == "2":
            remove_specific_domain(session)
        elif c == "3":
            show_all_domains(session)
        elif c == "4":
            print("\nSMTP config reset placeholder.\n")
        elif c == "0":
            break
        else:
            print("❌ Invalid.\n")

# ─────────────────────────────────────────
# Main menu loop
# ─────────────────────────────────────────

def main_menu_loop(session, token, zone_id, domain):
    while True:
        # live data
        zone_raw = get_zone_status_raw(session, zone_id)
        status_human = zone_status_display(zone_raw)
        total_dns  = len(list_dns(session, zone_id))

        print("\n╭──────────────────────────────────────────╮")
        print("│ Cloudflare DNS Manager v10.2 (GLOBAL)   │")
        print("│     Developed by MHR Dev Team 🌿         │")
        print("╰──────────────────────────────────────────╯\n")

        print(f" Domain Name         : {domain}")
        print(f" Domain Status       : {status_human}")
        print(f" Total DNS Records   : {total_dns}")
        print("────────────────────────────────────────────")
        print(" [1] Create DNS Records")
        print(" [2] Create DNS (Random)")
        print(" [3] Delete DNS Records")
        print(" [4] DNS List (Normal View)")
        print(" [5] DNS List (Pro View)")
        print(" [6] Name Server Manager")
        print(" [7] SSL/TLS Mode Manager")
        print(" [8] Tools")
        print(" [9] Exit")
        print(" [0] Logout")
        print("────────────────────────────────────────────")

        choice = input(" Select Option (0-9): ").strip()

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
        elif choice == "0":
            print("\n🔐 Logging out...")
            clear_auth()
            print("🧹 Saved credentials cleared (if existed).")
            print("👋 Logged out.\n")
            time.sleep(0.4)
            break
        else:
            print("❌ Invalid option.\n")

# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────

def main():
    # Step 1: login using email + global API key (or saved)
    token, zone_id, domain = login_global_flow()

    # Step 2: build session with scoped token
    session = requests.Session()
    session.headers.update(cf_headers(token))

    # Step 3: go to main menu loop
    main_menu_loop(session, token, zone_id, domain)

if __name__ == "__main__":
    main()
