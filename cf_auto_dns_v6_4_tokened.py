#!/usr/bin/env python3
"""
Cloudflare Auto DNS Manager v6.4 (Token Protected - Final Edition)
Author: MHR Dev Team 🌿
"""

import os, sys, time, json, hmac, hashlib, base64, re, subprocess

SECRET_KEY = os.getenv("TOKEN_SECRET", None)

# ---------------- BASIC UTILS ---------------- #
def b64u_decode(s: str) -> bytes:
    s2 = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s2.encode())

def verify_token(token: str, secret: str):
    try:
        parts = token.strip().split(".")
        if len(parts) != 2:
            return False, "token format invalid"
        payload_b64, sig_b64 = parts
        payload_json = b64u_decode(payload_b64)
        sig = b64u_decode(sig_b64)
        expected_sig = hmac.new(secret.encode(), payload_json, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected_sig):
            return False, "signature mismatch"
        payload = json.loads(payload_json.decode())
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            return False, "invalid expiry in token"
        if time.time() > float(exp):
            return False, "token expired"
        return True, ""
    except Exception as e:
        return False, f"verification error: {e}"

GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

# ---------------- SYSTEM SETUP ---------------- #
def run_cmd(cmd): return subprocess.call(cmd, shell=True)

def install_dependencies():
    print(f"{CYAN}🔧 Checking and installing required packages...{RESET}")
    run_cmd("apt update -y >/dev/null 2>&1")
    pkgs = ["python3", "python3-pip", "curl", "git", "nano", "zip"]
    for p in pkgs: run_cmd(f"apt install -y {p} >/dev/null 2>&1")
    print(f"{GREEN}✅ All required packages installed!{RESET}\n")

def ensure_requests():
    try: import requests
    except ImportError:
        print(f"{YELLOW}Installing 'requests'...{RESET}")
        run_cmd("pip3 install requests >/dev/null 2>&1")

def safe_request(action, *args, retries=4, delay=1.5, **kwargs):
    import requests
    for i in range(retries):
        try: return action(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"{YELLOW}⚠ Retry {i+1}/{retries}: {e}{RESET}")
            time.sleep(delay); delay *= 1.5
    raise

def progress_bar(prefix, name, dur=0.6):
    width = 25
    for i in range(0, width + 1):
        filled = "█" * i
        empty = "░" * (width - i)
        pct = int((i / width) * 100)
        sys.stdout.write(f"\r{CYAN}[{prefix}] {name} |{filled}{empty}| {pct:3d}%{RESET}")
        sys.stdout.flush()
        time.sleep(dur / width)
    sys.stdout.write("\n")

def cf_headers(token): return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
def validate_domain(domain): return bool(re.match(r"^(?!-)([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$", domain))

# ---------------- API UTIL ---------------- #
def list_all_records(sess, zone):
    import requests
    results = []; page = 1; per_page = 100
    while True:
        r = safe_request(sess.get, f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                         params={"per_page": per_page, "page": page})
        j = r.json(); chunk = j.get("result", [])
        if not chunk: break
        results.extend(chunk)
        if len(chunk) < per_page: break
        page += 1
    return results

def read_ips_paste():
    print(f"{CYAN}\nPaste IPs (one per line). Finish with empty line then press Enter:{RESET}")
    ips = []
    while True:
        try: line = input().strip()
        except EOFError: break
        if not line: break
        ips.append(line)
    return ips

# ---------------- CREATE DNS ---------------- #
def action_create(sess, zone, domain):
    base = input("Enter base name (us/uk/gb/ca or custom): ").strip().lower()
    if not base: print(f"{RED}❌ Base name required{RESET}"); return
    ttl = int(input("Enter TTL (default 120): ") or "120")
    sleep = float(input("Sleep between requests (default 0.5): ") or "0.5")
    ips = read_ips_paste()
    if not ips: print(f"{YELLOW}⚠ No IPs provided{RESET}"); return
    if input(f"{YELLOW}Confirm to CREATE {len(ips)} records? (y/n): {RESET}").strip().lower() != "y":
        print("Cancelled."); return
    created = 0
    for idx, ip in enumerate(ips, start=1):
        name = f"{base}{idx}.{domain}"
        progress_bar("CREATE", name)
        try:
            safe_request(sess.post, f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                         json={"type":"A","name":name,"content":ip,"ttl":ttl,"proxied":False})
            print(f"{GREEN}✅ Created {name} → {ip}{RESET}")
            created += 1
        except Exception as e:
            print(f"{RED}❌ Error {name}: {e}{RESET}")
        time.sleep(sleep)
    print(f"{GREEN}🎯 Done creating {created} records.{RESET}")

# ---------------- DELETE DNS (UPDATED) ---------------- #
def action_delete(sess, zone, domain):
    print(f"""\n{CYAN}🗑 Delete DNS Records Menu{RESET}
1) Delete a specific DNS record
2) Delete multiple DNS records (range)
3) Delete all DNS records
4) Back to main menu
""")

    choice = input("Choose (1-4): ").strip()

    # Option 1: Specific
    if choice == "1":
        name = input("Enter full DNS name to delete (e.g. us1.example.com): ").strip().lower()
        if not name:
            print(f"{RED}❌ DNS name required.{RESET}"); return
        if input(f"Confirm delete '{name}'? (y/n): ").strip().lower() != "y":
            print("Cancelled."); return
        progress_bar("DELETE", name)
        try:
            r = safe_request(sess.get, f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                             params={"type":"A","name":name})
            j = r.json()
            if j.get("result"):
                rec_id = j["result"][0]["id"]
                safe_request(sess.delete, f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rec_id}")
                print(f"{RED}🗑 Deleted {name}{RESET}")
            else:
                print(f"{YELLOW}⚠ Record not found: {name}{RESET}")
        except Exception as e:
            print(f"{RED}❌ {e}{RESET}")
        return

    # Option 2: Range delete
    elif choice == "2":
        base = input("Enter base name (e.g. us): ").strip().lower()
        cnt = int(input("How many records to delete?: ") or "0")
        if cnt <= 0: print(f"{YELLOW}⚠ Invalid number.{RESET}"); return
        if input(f"{YELLOW}Confirm delete {cnt} {base} records? (y/n): {RESET}").strip().lower() != "y":
            print("Cancelled."); return
        deleted = 0
        for i in range(1, cnt+1):
            name = f"{base}{i}.{domain}"
            progress_bar("DELETE", name)
            try:
                r = safe_request(sess.get, f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                                 params={"type":"A","name":name})
                j = r.json()
                if j.get("result"):
                    rec_id = j["result"][0]["id"]
                    safe_request(sess.delete, f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rec_id}")
                    print(f"{RED}🗑 Deleted {name}{RESET}")
                    deleted += 1
                else:
                    print(f"{YELLOW}⚠ Not found {name}{RESET}")
            except Exception as e:
                print(f"{RED}❌ {e}{RESET}")
        print(f"{GREEN}✅ Deleted {deleted} record(s).{RESET}")
        return

    # Option 3: Delete all
    elif choice == "3":
        print(f"{YELLOW}⚠ WARNING: This will delete ALL DNS records for this zone!{RESET}")
        if input("Type 'CONFIRM' to continue: ").strip() != "CONFIRM":
            print("Cancelled."); return
        recs = list_all_records(sess, zone)
        if not recs:
            print(f"{YELLOW}⚠ No records found.{RESET}"); return
        total = len(recs); deleted = 0
        for r in recs:
            name = r.get("name"); rec_id = r.get("id")
            progress_bar("DELETE", name)
            try:
                safe_request(sess.delete, f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rec_id}")
                print(f"{RED}🗑 Deleted {name}{RESET}")
                deleted += 1
            except Exception as e:
                print(f"{RED}❌ {e}{RESET}")
        print(f"{GREEN}✅ Deleted {deleted}/{total} records successfully!{RESET}")
        return

    else:
        print(f"{YELLOW}↩ Returning to main menu...{RESET}")
        return

# ---------------- LIST FUNCTIONS ---------------- #
def action_list(sess, zone, domain):
    print(f"{CYAN}📜 Fetching DNS list...{RESET}")
    recs = list_all_records(sess, zone)
    if not recs:
        print(f"{YELLOW}No DNS records found.{RESET}"); return
    for r in recs:
        print(f"{GREEN}{r.get('name'):<40}{RESET} → {r.get('content')}")
    print(f"{CYAN}Total records: {len(recs)}{RESET}")

def action_list_pro_compact(sess, zone, domain):
    print(f"{CYAN}🔍 Fetching DNS records (Pro Compact)...{RESET}")
    recs = list_all_records(sess, zone)
    if not recs:
        print(f"{YELLOW}⚠ No DNS records found for this zone.{RESET}"); return
    names = [r.get('name','') for r in recs if r.get('name')]
    result = "~".join(names)
    print(f"\n{GREEN}{result}{RESET}\n")
    print(f"{CYAN}✅ Total DNS records listed: {len(names)}{RESET}")
    try:
        with open("dns_list.txt","w") as f: f.write(result)
        print(f"{YELLOW}💾 DNS list saved to dns_list.txt{RESET}")
    except Exception as e:
        print(f"{RED}❌ Could not save list: {e}{RESET}")

# ---------------- MAIN MENU ---------------- #
def main_menu(sess, zone, domain):
    while True:
        print(f"""\n{BOLD}{CYAN}Cloudflare DNS Manager v6.4 (Token Protected){RESET}
1) Create DNS
2) Delete DNS
3) List DNS
4) List DNS (Pro)
5) Exit
""")
        choice = input("Choose (1-5): ").strip()
        if choice == "1": action_create(sess, zone, domain)
        elif choice == "2": action_delete(sess, zone, domain)
        elif choice == "3": action_list(sess, zone, domain)
        elif choice == "4": action_list_pro_compact(sess, zone, domain)
        elif choice == "5":
            print(f"{YELLOW}👋 Exiting Cloudflare DNS Manager...{RESET}")
            time.sleep(0.8)
            print(f"{GREEN}✅ Session Closed Successfully.{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}❌ Invalid option, try again.{RESET}")

# ---------------- ENTRY ---------------- #
def entrypoint():
    print("=== Protected Cloudflare Auto DNS Manager v6.4 ===")
    token = input("Enter access token: ").strip()
    secret = SECRET_KEY
    if not secret:
        print("ERROR: TOKEN_SECRET not set. Use export TOKEN_SECRET=\"your-secret\"")
        sys.exit(1)
    ok, reason = verify_token(token, secret)
    if not ok:
        print(f"Access denied: {reason}")
        sys.exit(1)
    install_dependencies()
    ensure_requests()
    import requests
    print("Token valid — starting DNS manager.\n")
    cf_token = input("Enter Cloudflare API Token: ").strip()
    zone_id = input("Enter Cloudflare Zone ID: ").strip()
    domain = input("Enter Domain (example.com): ").strip()
    if not validate_domain(domain):
        print("Invalid domain format."); sys.exit(1)
    sess = requests.Session()
    sess.headers.update(cf_headers(cf_token))
    main_menu(sess, zone_id, domain)

if __name__ == "__main__":
    entrypoint()
