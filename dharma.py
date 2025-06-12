#!/usr/bin/env python3
# dharma.py — Red Team Orchestrator with Safe Handoffs
# Author: Braxton Bailey (@Jimi421)

import argparse
import subprocess
import os
import sys
import json

ROOT = os.path.dirname(os.path.abspath(__file__))
RECON       = os.path.join(ROOT, "utils", "recon", "http_recon.py")
BRUTE       = os.path.join(ROOT, "utils", "bruteforce", "http_brute.py")
AUTO_NSE    = os.path.join(ROOT, "utils", "auto-nse.py")
AUTO_EXP    = os.path.join(ROOT, "utils", "auto-exploit.py")
LOOT_DIR    = os.path.join(ROOT, "loot")

def run(cmd):
    print(f"\n[+] Running: {cmd}")
    subprocess.call(cmd, shell=True)

def confirm(prompt):
    return input(f"\n[?] {prompt} [y/N]: ").strip().lower() == "y"

def run_recon(target):
    cmd = f"python3 {RECON} --target {target}"
    run(cmd)

def list_loot():
    files = sorted(f for f in os.listdir(LOOT_DIR) if f.startswith("http-"))
    if not files:
        print("[!] No loot files found.")
        return None
    print("\n[+] Available loot files:")
    for i, f in enumerate(files):
        print(f"  [{i}] {f}")
    idx = input("Select a file number to continue: ")
    try:
        return os.path.join(LOOT_DIR, files[int(idx)])
    except:
        print("[!] Invalid selection.")
        return None

def load_loot(path):
    with open(path) as f:
        return json.load(f)

def prompt_brute(loot):
    for login in loot.get("logins", []):
        print(f"\n[+] Login page found: {login['url']}")
        method = login.get("method", "form")
        if method == "form":
            print(f"    Fields: {login['username_field']} / {login['password_field']}")
        if confirm("→ Launch brute-force attack with level=fast?"):
            path = login["url"].split(".com")[-1]
            cmd = f"python3 {BRUTE} --target {loot['target']}{path} --level fast"
            run(cmd)

def prompt_nse(loot):
    if confirm("→ Launch auto-nse scan based on loot?"):
        cmd = f"python3 {AUTO_NSE} --target {loot['target']}"
        run(cmd)

def prompt_exploit():
    if confirm("→ Launch auto-exploit?"):
        run(f"python3 {AUTO_EXP}")

def main():
    parser = argparse.ArgumentParser(description="🔱 Dharma Red Team Orchestrator")
    parser.add_argument("--target", help="Target host (e.g. http://10.10.10.42)")
    args = parser.parse_args()

    if not args.target:
        print("[!] Please specify --target")
        sys.exit(1)

    print(f"\n🔱 Dharma Starting on Target: {args.target}")
    print("─────────────────────────────────────────────")

    # Phase 1: Recon
    if confirm("→ Begin recon phase?"):
        run_recon(args.target)

    # Phase 2: Loot Review + Brute
    if confirm("→ Review recon loot for bruteforce targets?"):
        loot_path = list_loot()
        if loot_path:
            loot = load_loot(loot_path)
            prompt_brute(loot)
            prompt_nse(loot)

    # Phase 3: Exploit
    prompt_exploit()

    print("\n[✓] Dharma complete. Review your loot folder.")
    print("🔚─────────────────────────────────────────────")

if __name__ == "__main__":
    main()

