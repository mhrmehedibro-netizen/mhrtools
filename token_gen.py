#!/usr/bin/env python3
"""
token_gen.py
Cloudflare DNS Manager v6.4 - Token Generator
Author: MHR Dev Team 🌿
"""

import argparse, time, json, hmac, hashlib, base64, datetime

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def make_token(secret: str, days: int = 5, user_id: str = "") -> (str, int):
    exp = int(time.time()) + int(days) * 24 * 3600
    payload = {"exp": exp}
    if user_id:
        payload["id"] = user_id
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(secret.encode(), payload_json, hashlib.sha256).digest()
    token = f"{b64u(payload_json)}.{b64u(sig)}"
    return token, exp

def main():
    parser = argparse.ArgumentParser(description="Generate signed access token for cf_auto_dns_v6_4.")
    parser.add_argument("--secret", "-s", required=True, help="Shared secret (must match TOKEN_SECRET)")
    parser.add_argument("--days", "-d", type=int, default=5, help="Token valid duration in days (default 5)")
    parser.add_argument("--id", "-i", default="", help="Optional user ID or tag")
    args = parser.parse_args()

    token, exp = make_token(args.secret, args.days, args.id)
    exp_str = datetime.datetime.utcfromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S UTC")

    print("\n🔑 Your Access Token:\n")
    print(token)
    print("\n🕒 Expires at:", exp_str)
    if args.id:
        print("👤 ID:", args.id)
    print(f"\n✅ Token valid for {args.days} day(s).")
    print("\n⚙️ Use this same secret in main script via:\nexport TOKEN_SECRET=\"{}\"".format(args.secret))
    print("Then run: python3 cf_auto_dns_v6_4_tokened.py\n")

if __name__ == "__main__":
    main()
