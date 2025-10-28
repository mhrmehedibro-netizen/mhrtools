#!/usr/bin/env python3
# ============================================================
# Cloudflare DNS Manager v10.8_full_stable (GLOBAL)
# Made by MHR 🌿 | MHR Dev Team
#
# THIS IS YOUR MAIN SCRIPT. ALL FUTURE PATCHES APPLY HERE.
#
# Features:
#  - Login with Cloudflare Email + Global API Key (visible input)
#  - Saves auth in /root/.cf_global_auth so next run doesn't ask
#  - If saved auth is wrong → auto clear → ask again
#  - Logout clears auth + exits, so next run will ask again
#
#  - Domain picker if multiple zones
#  - Menu header with aligned border box
#  - Shows:
#       Domain Name
#       Domain Status (✔️ Active / ⚠️ Suspended)
#       Total DNS Records
#
#  - DNS Create (prefix+serial: us1, us2, us3…)
#  - DNS Create (Random subdomain)
#  - Create shows compact progress bar + per-record result + total time summary
#
#  - Delete DNS:
#       1) Delete exact DNS name
#       2) Delete by prefix group (ex: "us" → us1/us2/us3…)
#       3) Delete ALL (single confirm)
#
#  - DNS List (Normal View):
#       sub.domain.tld IP
#       saved -> dns_list_normal.txt
#
#  - DNS List (Pro View + Export/Email):
#       • Groups DNS by prefix (us / uk / ca / etc)
#       • Shows each prefix group with its flag
#       • Prints all hostnames joined with "~"
#       • Saves pretty view -> dns_list_pro.txt
#       • Lets you [E] Export for sharing
#
#    Export mode:
#       - Build /root/dns_group_list.txt
#       - For each prefix:
#           🇺🇸 US GROUPS:
#           Group 1:
#           us1.example.com~us2.example.com
#
#           Group 2:
#           us3.example.com~us4.example.com
#
#           Group 3:
#           ...
#
#         (Each group block separated by blank line, exactly how you asked)
#
#       - Then email that TXT FILE as attachment to your mailbox
#         (sender = receiver = your Gmail)
#         Body will just say:
#            "Your grouped DNS records attached."
#
#  - Name Server Manager:
#       shows Cloudflare-assigned nameservers for this zone
#
#  - SSL/TLS Mode Manager:
#       view current mode
#       change to Flexible / Full / Strict
#
#  - Tools:
#       - Add Domain (root zone, jump_start=True)
#       - Remove Domain (delete zone)
#       - Show All Domains (saves to domain_list.txt)
#
#  - Flags map for groups (us→🇺🇸, uk→🇬🇧, etc)
#
# ============================================================

import os, sys, time, json, re, random, string, requests, smtplib
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

VERSION   = "v10.8_full_stable (GLOBAL)"
DEV_TAG   = "Developed by MHR Dev Team 🌿"
AUTH_FILE = "/root/.cf_global_auth"

# Gmail config (sender == receiver)
MAIL_FROM         = "riyajuddin778@gmail.com"
MAIL_TO           = "riyajuddin778@gmail.com"
MAIL_APP_PASSWORD = "elqdujxsqiptzimo"

DIV = "────────────────────────────────────────────"

FLAG_MAP = {
    "us": "🇺🇸","uk":"🇬🇧","gb":"🇬🇧","ca":"🇨🇦","bd":"🇧🇩","in":"🇮🇳","au":"🇦🇺","de":"🇩🇪","fr":"🇫🇷",
    "jp":"🇯🇵","cn":"🇨🇳","nl":"🇳🇱","es":"🇪🇸","it":"🇮🇹","br":"🇧🇷","ru":"🇷🇺","se":"🇸🇪","no":"🇳🇴",
    "fi":"🇫🇮","kr":"🇰🇷","sg":"🇸🇬","hk":"🇭🇰","nz":"🇳🇿","za":"🇿🇦","mx":"🇲🇽","ar":"🇦🇷","ch":"🇨🇭",
    "pl":"🇵🇱","pt":"🇵🇹","ie":"🇮🇪","tr":"🇹🇷","ae":"🇦🇪","sa":"🇸🇦","id":"🇮🇩","ph":"🇵🇭","vn":"🇻🇳",
    "pk":"🇵🇰","eg":"🇪🇬","mhr":"🌿","other":"🏳️"
}

# -------------------------------------------------
# Helpers / Auth storage
# -------------------------------------------------

def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")

def cf_headers(email, key):
    return {
        "X-Auth-Email": email,
        "X-Auth-Key":   key,
        "Content-Type": "application/json"
    }

def save_auth(email, key):
    with open(AUTH_FILE, "w") as f:
        json.dump({"email": email, "key": key}, f)

def load_auth():
    if not os.path.exists(AUTH_FILE):
        return None
    try:
        data = json.load(open(AUTH_FILE))
        return data.get("email"), data.get("key")
    except:
        return None

def clear_auth():
    if os.path.exists(AUTH_FILE):
        os.remove(AUTH_FILE)

def natural_sort_key(name: str):
    return [int(t) if t.isdigit() else t.lower()
            for t in re.split(r'([0-9]+)', name)]

def short_progress(prefix, current, total, start_time):
    if total <= 0:
        total = 1
    ratio = current / total
    width = 12
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(ratio * 100)
    elapsed = time.perf_counter() - start_time
    sys.stdout.write(
        f"\r{prefix} ({current}/{total}) |{bar}| {pct}%  ⏱ {elapsed:.2f}s"
    )
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")

# -------------------------------------------------
# Cloudflare basic calls
# -------------------------------------------------

def fetch_zones(email, key):
    print("🌐 Checking Cloudflare Credentials / Fetching Zones...", end="", flush=True)
    try:
        r = requests.get(
            "https://api.cloudflare.com/client/v4/zones",
            headers=cf_headers(email, key),
            timeout=20
        )
    except Exception:
        print(" ❌")
        return None
    print(" ✅ Done")

    if r.status_code != 200:
        return None
    body = r.json()
    if not body.get("success"):
        return None
    return body.get("result", [])

def pick_zone(zones):
    print("\nAvailable Domains:")
    print(DIV)
    for i, z in enumerate(zones, start=1):
        print(f"{i}) {z['name']}  ({z.get('status','')})")
    print(DIV)
    while True:
        ch = input("Select domain number: ").strip()
        if not ch.isdigit():
            print("❌ Invalid. Try again.")
            continue
        idx = int(ch)
        if idx < 1 or idx > len(zones):
            print("❌ Out of range.")
            continue
        chosen = zones[idx-1]
        zid = chosen["id"]
        dom = chosen["name"]
        st  = chosen.get("status","")
        return zid, dom, st

def list_dns_records(email, key, zone_id):
    r = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        headers=cf_headers(email, key),
        timeout=20
    )
    data = r.json()
    return data.get("result", [])

def get_zone_details(email, key, zone_id):
    r = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}",
        headers=cf_headers(email, key),
        timeout=20
    )
    if r.status_code != 200:
        return None
    data = r.json()
    if not data.get("success"):
        return None
    return data.get("result")

def zone_status_label(raw_status):
    if str(raw_status).lower() in ["active","pending"]:
        return "✔️ Active"
    return "⚠️ Suspended"

# -------------------------------------------------
# DNS create
# -------------------------------------------------

def timed_input_list(prompt="Paste IPs (one per line). Press Enter twice to finish:"):
    print(prompt)
    ips = []
    while True:
        line = input().strip()
        if line == "":
            break
        ips.append(line)
    return ips

def random_label():
    L = random.randint(5,8)
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(L))

def create_record(email, key, zone_id, name, ip):
    payload = {
        "type": "A",
        "name": name,
        "content": ip,
        "ttl": 1,
        "proxied": False
    }
    r = requests.post(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        headers=cf_headers(email, key),
        json=payload,
        timeout=20
    )
    ok = (r.status_code == 200 and r.json().get("success"))
    return ok, r.text if not ok else "OK"

def create_dns_sequence(email, key, zone_id, domain_name):
    base = input("\nBase prefix (ex: us / uk / ca): ").strip().lower()
    ips  = timed_input_list("Paste IPs (1 per line). Enter on blank line to finish:")
    if not ips:
        print("❌ No IPs. Cancel.\n")
        return

    start_t = time.perf_counter()
    total = len(ips)
    print("\n⚙️ Creating DNS Records...\n")

    done_count = 0
    for idx, ip in enumerate(ips, start=1):
        sub = f"{base}{idx}.{domain_name}"
        short_progress("⚙️ Creating", idx, total, start_t)
        ok, msg = create_record(email, key, zone_id, sub, ip)
        if ok:
            print(f"\n✅ {sub} {ip} created.")
            done_count += 1
        else:
            print(f"\n❌ Failed {sub} {ip}")
            print(msg)

    total_time = time.perf_counter() - start_t
    print("\n✅ DNS Records Created Successfully!")
    print(f"    Total Created : {done_count}")
    print(f"    Time Taken    : {total_time:.2f} seconds\n")

def create_dns_random(email, key, zone_id, domain_name):
    ips = timed_input_list("Paste IPs (1 per line). Enter blank to finish:")
    if not ips:
        print("❌ No IPs. Cancel.\n")
        return

    start_t = time.perf_counter()
    total = len(ips)
    print("\n⚙️ Creating DNS Records (Random)...\n")

    done_count = 0
    for idx, ip in enumerate(ips, start=1):
        sub = f"{random_label()}.{domain_name}"
        short_progress("⚙️ Creating", idx, total, start_t)
        ok, msg = create_record(email, key, zone_id, sub, ip)
        if ok:
            print(f"\n✅ {sub} {ip} created.")
            done_count += 1
        else:
            print(f"\n❌ Failed {sub} {ip}")
            print(msg)

    total_time = time.perf_counter() - start_t
    print("\n✅ DNS Records Created Successfully!")
    print(f"    Total Created : {done_count}")
    print(f"    Time Taken    : {total_time:.2f} seconds\n")

# -------------------------------------------------
# DNS delete
# -------------------------------------------------

def cf_get_dns_filtered(email, key, zone_id, params=None):
    r = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        headers=cf_headers(email, key),
        params=params,
        timeout=20
    )
    return r.json().get("result", [])

def delete_single_dns(email, key, zone_id):
    name = input("Full DNS name to delete: ").strip()
    if not name:
        print("❌ No name.")
        return
    recs = cf_get_dns_filtered(email, key, zone_id, {"name": name})
    if not recs:
        print("❌ Not found.")
        return
    rid = recs[0]["id"]
    r = requests.delete(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}",
        headers=cf_headers(email, key),
        timeout=20
    )
    if r.status_code == 200 and r.json().get("success"):
        print(f"🗑️ Deleted: {name}")
    else:
        print("❌ Delete failed.")

def delete_group_dns(email, key, zone_id):
    prefix = input("Group prefix (ex: us): ").strip().lower()
    if not prefix:
        print("❌ No prefix.")
        return

    allrecs = list_dns_records(email, key, zone_id)
    targets = []
    for r in allrecs:
        nm = r.get("name","")
        first_label = nm.split(".")[0]
        m = re.match(r"^([a-zA-Z]+)", first_label)
        grp = m and m.group(1).lower() or ""
        if grp == prefix:
            targets.append((r["id"], nm))

    if not targets:
        print("⚠ No DNS matched that prefix.")
        return

    print(f"Found {len(targets)} record(s) in group '{prefix}':")
    for _,n in targets:
        print(" •",n)
    confirm = input("Delete them all? (y/n): ").strip().lower()
    if confirm != "y":
        print("❌ Cancel.")
        return

    start_t = time.perf_counter()
    for idx, (rid,nm) in enumerate(targets, start=1):
        short_progress("🗑️ Deleting", idx, len(targets), start_t)
        requests.delete(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}",
            headers=cf_headers(email, key),
            timeout=20
        )
        print(f"\n🗑️ Deleted: {nm}")

    total_t = time.perf_counter() - start_t
    print(f"\n✅ Deleted group '{prefix}' total {len(targets)} in {total_t:.2f}s\n")

def delete_all_dns(email, key, zone_id):
    confirm = input("⚠ Delete ALL DNS records? (y/n): ").lower()
    if confirm != "y":
        print("❌ Cancelled.")
        return

    recs = list_dns_records(email, key, zone_id)
    if not recs:
        print("No DNS to delete.")
        return

    start_t = time.perf_counter()
    for idx, r in enumerate(recs, start=1):
        nm = r["name"]
        rid = r["id"]
        short_progress("🗑️ Deleting", idx, len(recs), start_t)
        requests.delete(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}",
            headers=cf_headers(email, key),
            timeout=20
        )
        print(f"\n🗑️ Deleted: {nm}")

    total_t = time.perf_counter() - start_t
    print(f"\n✅ Deleted ALL ({len(recs)}) in {total_t:.2f}s\n")

def delete_dns_menu(email, key, zone_id):
    while True:
        print("\n🧹 DNS Delete Menu")
        print(" 1) Delete by exact DNS name")
        print(" 2) Delete by group prefix (ex: 'us' -> us1/us2/us3...)")
        print(" 3) Delete ALL records (danger)")
        print(" 0) Back")
        ch = input("Choose: ").strip()

        if ch == "0": return
        elif ch == "1":
            delete_single_dns(email, key, zone_id)
        elif ch == "2":
            delete_group_dns(email, key, zone_id)
        elif ch == "3":
            delete_all_dns(email, key, zone_id)
        else:
            print("❌ Invalid.")

# -------------------------------------------------
# DNS List (Normal View)
# -------------------------------------------------

def list_normal_view(email, key, zone_id):
    print("\n⏳ Loading DNS Records...")
    recs = list_dns_records(email, key, zone_id)
    print("✅ Loaded.\n")

    out_lines = []
    for r in recs:
        nm = r.get("name","")
        ip = r.get("content","")
        line = f"{nm} {ip}"
        print(line)
        out_lines.append(line)

    with open("dns_list_normal.txt","w") as f:
        for L in out_lines:
            f.write(L+"\n")

    print("\n📄 Saved to dns_list_normal.txt\n")

# -------------------------------------------------
# DNS List (Pro View) + Export
# -------------------------------------------------

def group_records_by_prefix(dns_records):
    groups = {}
    for r in dns_records:
        full = r.get("name","")
        first_label = full.split(".")[0] if full else ""
        m = re.match(r"^([a-zA-Z]+)", first_label)
        prefix = m.group(1).lower() if m else "other"
        groups.setdefault(prefix, []).append(full)
    for p in groups:
        groups[p].sort(key=natural_sort_key)
    return groups

def split_into_three_chunks(lst):
    # up to 3 chunks, nearly even
    result_chunks = []
    if not lst:
        return result_chunks

    n = len(lst)
    if n <= 3:
        # each item alone OR single chunk? You wanted 3 groups style,
        # but if small we'll still just create 1..n groups separated with blank lines
        for item in lst:
            result_chunks.append([item])
        return result_chunks

    base = n // 3
    rem  = n % 3
    sizes = []
    for _ in range(3):
        sz = base + (1 if rem>0 else 0)
        if sz > 0:
            sizes.append(sz)
            rem -= 1

    i = 0
    for sz in sizes:
        result_chunks.append(lst[i:i+sz])
        i += sz
    return result_chunks

def build_group_export_text(groups):
    """
    Build body text for dns_group_list.txt exactly in your format:
    <flag> <PREFIX> GROUPS:
    Group 1:
    <a1~a2~a3>

    Group 2:
    <...>

    (blank line between group blocks)
    """
    lines_out = []
    for prefix, hostnames in groups.items():
        flag = FLAG_MAP.get(prefix.lower(),"🏳️")
        lines_out.append(f"{flag} {prefix.upper()} GROUPS:")

        chunks = split_into_three_chunks(hostnames)
        for idx, chunk in enumerate(chunks, start=1):
            joined = "~".join(chunk)
            lines_out.append(f"Group {idx}:")
            lines_out.append(joined)
            lines_out.append("")  # blank line after each group

        # extra blank line after each prefix block
        lines_out.append("")

    return "\n".join(lines_out)

def save_group_export_file(groups, path="/root/dns_group_list.txt"):
    txt = build_group_export_text(groups)
    with open(path, "w") as f:
        f.write(txt)
    return path

def send_file_via_email(filepath):
    # build email with attachment
    subject = "DNS Group Export"
    body    = "Your grouped DNS records attached."

    msg = MIMEMultipart()
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO
    msg["Subject"] = subject

    # body text
    msg.attach(MIMEText(body, "plain"))

    # attach file
    try:
        with open(filepath, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f'attachment; filename="{os.path.basename(filepath)}"'
        )
        msg.attach(part)
    except Exception as e:
        print("❌ Could not attach file:", e)
        return False

    try:
        smtp = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        smtp.login(MAIL_FROM, MAIL_APP_PASSWORD)
        smtp.sendmail(MAIL_FROM, [MAIL_TO], msg.as_string())
        smtp.quit()
        return True
    except Exception as e:
        print("❌ Email send failed:", e)
        return False

def list_pro_view(email, key, zone_id):
    recs = list_dns_records(email, key, zone_id)
    groups = group_records_by_prefix(recs)

    print("\n✅ DNS Records Loaded (Pro View)\n")
    pro_lines = []
    for prefix, names in groups.items():
        flag = FLAG_MAP.get(prefix.lower(),"🏳️")
        joined = "~".join(names)
        print(f"{flag}  {prefix.upper()}")
        print(joined+"\n")

        pro_lines.append(f"{prefix.upper()}")
        pro_lines.append(joined)
        pro_lines.append("")

    with open("dns_list_pro.txt","w") as f:
        f.write("\n".join(pro_lines))
    print("📄 Saved to dns_list_pro.txt\n")

    while True:
        print("Options: [E] Export & Send TXT  |  [B] Back")
        choice = input("Choose: ").strip().lower()
        if choice == "b" or choice == "":
            return
        if choice == "e":
            # 1. build /root/dns_group_list.txt
            export_path = save_group_export_file(groups, "/root/dns_group_list.txt")
            print(f"\n📄 Export file created at: {export_path}")

            # 2. send that file via Gmail (as attachment)
            ok = send_file_via_email(export_path)
            if ok:
                print("✅ DNS groups exported and sent successfully!")
                print(f"📎 Attached file: {os.path.basename(export_path)}\n")
            else:
                print("⚠ Export file created, but email send failed.\n")
            input("Press Enter to continue...")
            return
        print("❌ Invalid.")

# -------------------------------------------------
# Name Server Manager
# -------------------------------------------------

def show_nameservers(email, key, zone_id):
    info = get_zone_details(email, key, zone_id)
    if not info:
        print("\n❌ Failed to fetch nameservers.\n")
        input("Press Enter to continue...")
        return
    ns_list = info.get("name_servers", [])
    if not ns_list:
        print("\n⚠ No Cloudflare nameservers yet (zone pending?).\n")
        input("Press Enter to continue...")
        return
    print("\n📡 Current Cloudflare Nameservers:")
    for i, ns in enumerate(ns_list, start=1):
        print(f" {i}. {ns}")
    print("")
    input("Press Enter to continue...")

# -------------------------------------------------
# SSL/TLS Mode Manager
# -------------------------------------------------

def ssl_tls_mode_manager(email, key, zone_id):
    print("\n🔐 Checking current SSL/TLS Mode...")
    r = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl",
        headers=cf_headers(email, key),
        timeout=20
    )

    if r.status_code == 403:
        print("⚠ Missing Zone Settings Edit permission.\n")
        input("Press Enter to continue...")
        return
    if r.status_code != 200:
        print("❌ Failed to fetch SSL mode.\n")
        input("Press Enter to continue...")
        return

    data = r.json()
    if not data.get("success"):
        print("❌ API error.\n")
        input("Press Enter to continue...")
        return

    current_mode = data["result"]["value"].capitalize()
    print(f"🌐 Current SSL/TLS Mode: {current_mode}\n")

    print("Available Modes:")
    print(" 1) Flexible")
    print(" 2) Full")
    print(" 3) Strict\n")
    choice = input("Select new mode (1-3) or Enter to skip: ").strip()
    mode_map = {"1":"flexible","2":"full","3":"strict"}
    if choice not in mode_map:
        print("⚠ No change.\n")
        input("Press Enter to continue...")
        return

    new_mode = mode_map[choice]
    print(f"🔄 Updating to {new_mode.capitalize()}...")
    r2 = requests.patch(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl",
        headers=cf_headers(email, key),
        json={"value": new_mode},
        timeout=20
    )

    if r2.status_code == 403:
        print("⚠ Missing Zone Settings Edit permission.\n")
    elif r2.status_code == 200 and r2.json().get("success"):
        print(f"✅ SSL/TLS mode changed to {new_mode.capitalize()}.\n")
    else:
        print("❌ Failed to update SSL mode.\n")

    input("Press Enter to continue...")

# -------------------------------------------------
# Tools Menu
# -------------------------------------------------

def list_all_domains(email, key):
    r = requests.get(
        "https://api.cloudflare.com/client/v4/zones",
        headers=cf_headers(email, key),
        timeout=20
    )
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"
    data = r.json()
    if not data.get("success"):
        return None, "API error"
    zs = data.get("result", [])
    arr = []
    for z in zs:
        arr.append({
            "id": z.get("id",""),
            "name": z.get("name",""),
            "status": z.get("status","")
        })
    return arr, None

def add_domain(email, key):
    new_domain = input("Enter ROOT domain to add (example.com): ").strip()
    if not new_domain:
        print("❌ No domain.\n")
        return
    if new_domain.count(".") < 1:
        print("❌ Invalid domain.\n")
        return
    if new_domain.count(".") >= 2:
        print("⚠ That looks like a subdomain. Must be root.\n")
        return

    payload = {"name": new_domain, "jump_start": True}
    r = requests.post(
        "https://api.cloudflare.com/client/v4/zones",
        headers=cf_headers(email, key),
        json=payload,
        timeout=20
    )

    if r.status_code == 200 and r.json().get("success"):
        res = r.json()["result"]
        zid    = res.get("id","?")
        status = res.get("status","?")
        print("✅ Domain added.")
        print("   Domain :", new_domain)
        print("   Zone ID:", zid)
        print("   Status :", status, "\n")
        with open("domain_activity_log.txt","a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}] ADDED {new_domain} zone_id={zid} status={status}\n")
    else:
        print("❌ Failed to add domain.")
        try:
            print(r.text+"\n")
        except:
            pass

def remove_domain(email, key):
    zones, err = list_all_domains(email, key)
    if not zones:
        print(f"❌ Could not list domains ({err}).\n")
        return

    print(f"\n🌐 Total Domains: {len(zones)}")
    print(DIV)
    for i,z in enumerate(zones, start=1):
        print(f"{i}) {z['name']}  → {z['status']}  [{z['id']}]")
    print(DIV+"\n")

    pick = input("Enter number to remove (or Enter to cancel): ").strip()
    if not pick.isdigit():
        print("❌ Cancel.\n")
        return
    idx = int(pick)
    if idx < 1 or idx > len(zones):
        print("❌ Invalid.\n")
        return

    target = zones[idx-1]
    dom    = target["name"]
    zid    = target["id"]

    sure = input(f"⚠ Really DELETE zone {dom}? (y/n): ").lower()
    if sure != "y":
        print("❌ Cancel.\n")
        return

    r = requests.delete(
        f"https://api.cloudflare.com/client/v4/zones/{zid}",
        headers=cf_headers(email, key),
        timeout=20
    )

    if r.status_code == 200 and r.json().get("success"):
        print(f"🗑️ Domain removed: {dom} (zone_id={zid})\n")
        with open("domain_activity_log.txt","a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}] REMOVED {dom} zone_id={zid}\n")
    else:
        print("❌ Failed to remove domain.\n")
        try:
            print(r.text+"\n")
        except:
            pass

def show_all_domains(email, key):
    zones, err = list_all_domains(email, key)
    if not zones:
        print(f"❌ Could not list domains ({err}).\n")
        return
    print(f"\n🌐 Total Domains: {len(zones)}")
    print(DIV)
    lines=[]
    for i,z in enumerate(zones, start=1):
        row = f"{i}) {z['name']}  → {z['status']}  [zone_id={z['id']}]"
        print(row)
        lines.append(row)
    print(DIV+"\n")

    with open("domain_list.txt","w") as f:
        for L in lines:
            f.write(L+"\n")

    print("📄 Saved to domain_list.txt\n")
    input("Press Enter to continue...")

def tools_menu(email, key):
    while True:
        print("\n🛠 Tools Menu")
        print("━━━━━━━━━━━━━━━━━━━")
        print("[1] Add Domain to Cloudflare")
        print("[2] Remove Domain from Cloudflare")
        print("[3] Show All Domains")
        print("[0] Back")
        print("━━━━━━━━━━━━━━━━━━━")

        c = input("Choose: ").strip()
        if c == "0":
            return
        elif c == "1":
            add_domain(email, key)
        elif c == "2":
            remove_domain(email, key)
        elif c == "3":
            show_all_domains(email, key)
        else:
            print("❌ Invalid.")

# -------------------------------------------------
# Login Flow (smart_login)
# -------------------------------------------------

def smart_login():
    """
    1. Try saved auth from /root/.cf_global_auth
    2. If invalid → clear and ask again
    3. Save new auth
    4. Return (email, key, zone_id, domain, status_label)
    """
    while True:
        saved = load_auth()
        if saved:
            email, key = saved
            zones = fetch_zones(email, key)
            if zones:
                zid, dom, st = pick_zone(zones)
                return email, key, zid, dom, zone_status_label(st)
            print("\n⚠️ Saved credentials invalid. Clearing and retrying...\n")
            clear_auth()

        print(f"🔐 Cloudflare Global Login ({VERSION})")
        email = input("Cloudflare Email : ").strip()
        key   = input("Global API Key   : ").strip()

        zones = fetch_zones(email, key)
        if not zones:
            print("❌ Login failed. Try again.\n")
            continue

        save_auth(email, key)
        print("✅ Credentials saved.\n")
        zid, dom, st = pick_zone(zones)
        return email, key, zid, dom, zone_status_label(st)

# -------------------------------------------------
# Main Menu Loop
# -------------------------------------------------

def main_menu_loop(email, key, zone_id, domain_name, status_label):
    while True:
        dns_recs  = list_dns_records(email, key, zone_id)
        total_dns = len(dns_recs)

        clear_screen()
        header_top    = "╭────────────────────────────────────────────╮"
        header_mid1   = "│   Cloudflare DNS Manager v10.8 (GLOBAL)    │"
        header_mid2   = "│        Developed by MHR Dev Team 🌿        │"
        header_bottom = "╰────────────────────────────────────────────╯"

        print(header_top)
        print(header_mid1)
        print(header_mid2)
        print(header_bottom)

        print(f" Domain Name        : {domain_name}")
        print(f" Domain Status      : {status_label}")
        print(f" Total DNS Records  : {total_dns}")
        print(DIV)
        print(" [1] Create DNS Records")
        print(" [2] Create DNS (Random)")
        print(" [3] Delete DNS Records")
        print(" [4] DNS List (Normal View)")
        print(" [5] DNS List (Pro View + Export/Email)")
        print(" [6] Name Server Manager")
        print(" [7] SSL/TLS Mode Manager")
        print(" [8] Tools")
        print(" [9] Logout / Clear Saved Auth")
        print(" [0] Exit (Keep Auth)")
        print(DIV)

        choice = input("Select Option (0-9): ").strip()

        if choice == "1":
            create_dns_sequence(email, key, zone_id, domain_name)
            input("Press Enter to continue...")
        elif choice == "2":
            create_dns_random(email, key, zone_id, domain_name)
            input("Press Enter to continue...")
        elif choice == "3":
            delete_dns_menu(email, key, zone_id)
            input("Press Enter to continue...")
        elif choice == "4":
            list_normal_view(email, key, zone_id)
            input("Press Enter to continue...")
        elif choice == "5":
            list_pro_view(email, key, zone_id)
            # list_pro_view handles its own pause
        elif choice == "6":
            show_nameservers(email, key, zone_id)
        elif choice == "7":
            ssl_tls_mode_manager(email, key, zone_id)
        elif choice == "8":
            tools_menu(email, key)
        elif choice == "9":
            clear_auth()
            print("🔒 Logged out. Auth cleared.\n")
            sys.exit(0)
        elif choice == "0":
            print("👋 Bye (auth kept).")
            sys.exit(0)
        else:
            print("❌ Invalid.")
            time.sleep(1)

# -------------------------------------------------
# Entry
# -------------------------------------------------

def main():
    email, key, zid, dom, st_label = smart_login()
    main_menu_loop(email, key, zid, dom, st_label)

if __name__ == "__main__":
    main()
