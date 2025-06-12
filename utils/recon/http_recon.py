#!/usr/bin/env python3
import requests
import argparse
import re
import json
import os
from urllib.parse import urljoin, urlparse
from datetime import datetime

requests.packages.urllib3.disable_warnings()

COMMON_PATHS = [
    "/login", "/admin", "/api/login", "/auth", "/signin", "/users/login",
    "/account/login", "/wp-login.php", "/dashboard", "/index.php", "/rest", "/api/auth"
]

def parse_login_fields(html):
    fields = re.findall(r'<input[^>]+name=["\']?([\w\-]+)["\']?', html, re.I)
    username_field, password_field = None, None
    for f in fields:
        if 'user' in f.lower() and not username_field:
            username_field = f
        if 'pass' in f.lower() and not password_field:
            password_field = f
    return username_field, password_field

def looks_like_json_login(response):
    if "application/json" in response.headers.get("Content-Type", ""):
        if "username" in response.text and "password" in response.text:
            return True
    return False

def save_loot(target, data):
    os.makedirs("loot", exist_ok=True)
    target_slug = target.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "")
    filename = f"loot/http-{target_slug}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Loot saved to {filename}")

def scan_http(target, quick=False):
    print(f"\n[+] Starting HTTP Recon: {target}")
    try:
        r = requests.get(target, timeout=5, verify=False)
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        return

    parsed = urlparse(target)
    host = parsed.hostname or target

    results = {
        "target": target,
        "title": "",
        "headers": dict(r.headers),
        "found_paths": [],
        "logins": [],
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    print("\n[+] Headers:")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")

    title = re.findall(r"<title>(.*?)</title>", r.text, re.I)
    results["title"] = title[0] if title else "N/A"
    print(f"\n[+] Page Title: {results['title']}")

    paths_to_check = COMMON_PATHS[:3] if quick else COMMON_PATHS

    print("\n[+] Checking common paths:")
    for path in paths_to_check:
        url = urljoin(target, path)
        try:
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            code = resp.status_code
            content_type = resp.headers.get("Content-Type", "")

            if code in [200, 302] and "html" in content_type.lower():
                print(f"    [FOUND] {url} ({code})")
                results["found_paths"].append(url)

                # Try to detect login form
                username_field, password_field = parse_login_fields(resp.text)
                if username_field and password_field:
                    print(f"      [FORM] Fields: {username_field}, {password_field}")
                    nse_cmd = f'nmap -p80 {host} --script ./nse/http-json-brute.nse ' \
                              f'--script-args "http-json-brute.path={path},' \
                              f'http-json-brute.username_field={username_field},' \
                              f'http-json-brute.password_field={password_field}"'
                    print(f"      [NSE Suggestion]:\n        {nse_cmd}")
                    results["logins"].append({
                        "url": url,
                        "method": "form",
                        "username_field": username_field,
                        "password_field": password_field,
                        "nse_command": nse_cmd
                    })

                elif looks_like_json_login(resp):
                    print(f"      [JSON LOGIN] Detected")
                    nse_cmd = f'nmap -p80 {host} --script ./nse/http-json-brute.nse ' \
                              f'--script-args "http-json-brute.path={path}"'
                    print(f"      [NSE Suggestion]:\n        {nse_cmd}")
                    results["logins"].append({
                        "url": url,
                        "method": "json",
                        "nse_command": nse_cmd
                    })

        except Exception:
            continue

    save_loot(host, results)

def cli():
    parser = argparse.ArgumentParser(description="HTTP recon tool for Dharma-Tools")
    parser.add_argument("target", help="Target base URL (e.g. http://10.10.10.42)")
    parser.add_argument("--quick", action="store_true", help="Limit to top 3 common paths")
    return parser.parse_args()

if __name__ == "__main__":
    args = cli()
    scan_http(args.target, quick=args.quick)

