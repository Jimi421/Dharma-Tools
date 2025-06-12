#!/usr/bin/env python3
import json, argparse, os, subprocess

def resolve_script(script_name):
    return f"./nse/{script_name}" if os.path.exists(f"./nse/{script_name}") else script_name

def load_loot(ip, proto):
    path = f"loot/{proto}-{ip.replace('.', '_')}.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def suggest_http(http_data, target):
    cmds = []
    if "logins" in http_data:
        for login in http_data["logins"]:
            if login["method"] == "form":
                path = login["url"].split("/", 3)[-1]
                script = resolve_script("http-json-brute.nse")
                cmd = f'nmap -p80 {target} --script {script} ' + \
                      f'--script-args "http-json-brute.path=/{path},' + \
                      f'http-json-brute.username_field={login["username_field"]},' + \
                      f'http-json-brute.password_field={login["password_field"]}"'
                cmds.append(("http", cmd))
    return cmds

def suggest_ftp(ftp_data, target):
    cmds = []
    if ftp_data.get("anonymous_login"):
        cmd = f'nmap -p21 {target} --script ftp-anon,ftp-user-enum'
        cmds.append(("ftp", cmd))
    return cmds

def suggest_smb(smb_data, target):
    cmds = []
    shares = smb_data.get("shares", [])
    if any(s["access"] != "NO ACCESS" for s in shares):
        script1 = resolve_script("smb-anon-hunter.nse")
        cmd = f'nmap -p445 {target} --script {script1},smb-enum-shares,smb-enum-users'
        cmds.append(("smb", cmd))
    return cmds

def auto_nse(target, modules=None, run=False, export_plan=None, dry_run_json=False, auto_chain=False, callback=None, loot_only=False):
    print(f"\n[+] Auto-NSE v3 starting for {target}")

    allowed = modules if modules else ["ftp", "smb", "http"]
    all_cmds = []

    # Load recon data
    http = load_loot(target, "http") if "http" in allowed else None
    ftp  = load_loot(target, "ftp")  if "ftp"  in allowed else None
    smb  = load_loot(target, "smb")  if "smb"  in allowed else None

    if dry_run_json:
        print("\n[+] Raw loot JSON dump:")
        for proto, loot in [("HTTP", http), ("FTP", ftp), ("SMB", smb)]:
            if loot:
                print(f"\n=== {proto} ===")
                print(json.dumps(loot, indent=2))

    if loot_only:
        print("[+] Loot-only mode: skipping NSE, using existing recon files.")
        return

    # Generate commands
    if http:
        print("[*] Found HTTP recon data")
        all_cmds += suggest_http(http, target)
    if ftp:
        print("[*] Found FTP recon data")
        all_cmds += suggest_ftp(ftp, target)
    if smb:
        print("[*] Found SMB recon data")
        all_cmds += suggest_smb(smb, target)

    if not all_cmds:
        print("[-] No actionable recon data or loot.")
        return

    results_dir = f"results/{target}/nmap"
    os.makedirs(results_dir, exist_ok=True)

    if export_plan:
        with open(export_plan, "w") as f:
            for proto, cmd in all_cmds:
                f.write(cmd + f" -oN {results_dir}/{proto}_nse.txt\n")
        print(f"\n[+] Exported NSE scan plan to {export_plan}")
        return

    # Execute or print commands
    for proto, cmd in all_cmds:
        full_cmd = f"{cmd} -oN {results_dir}/{proto}_nse.txt"
        print(f"\n>>> {full_cmd}")
        if run:
            subprocess.run(full_cmd, shell=True)

    # Chain to auto-exploit if desired
    if auto_chain:
        print(f"\n[+] Chaining into auto-exploit for {target}")
        chain_cmd = [
            "python3", "utils/auto-exploit.py",
            "--target", target
        ]
        if callback:
            chain_cmd += ["--callback", callback]
        subprocess.run(chain_cmd)

# === Entrypoint ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dharma Auto-NSE v3 (chain-ready)")
    parser.add_argument("--target", required=True, help="Target IP")
    parser.add_argument("--modules", help="Comma-separated: ftp,smb,http")
    parser.add_argument("--run", action="store_true", help="Run NSE scans")
    parser.add_argument("--export-plan", help="Save NSE commands to file")
    parser.add_argument("--dry-run-json", action="store_true", help="Print loot JSONs")
    parser.add_argument("--auto-chain", action="store_true", help="Run auto-exploit after NSE")
    parser.add_argument("--callback", help="Callback IP:PORT (for shell or RC)")
    parser.add_argument("--loot-only", action="store_true", help="Only parse loot, skip NSE")

    args = parser.parse_args()
    module_list = args.modules.split(",") if args.modules else None

    auto_nse(
        target=args.target,
        modules=module_list,
        run=args.run,
        export_plan=args.export_plan,
        dry_run_json=args.dry_run_json,
        auto_chain=args.auto_chain,
        callback=args.callback,
        loot_only=args.loot_only
    )

