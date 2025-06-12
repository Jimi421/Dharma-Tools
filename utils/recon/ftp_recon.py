#!/usr/bin/env python3
import ftplib
import argparse
import os
import json
from datetime import datetime, timezone
from io import BytesIO

def ftp_banner(msg):
    print(f"\n[+] {msg}")

def save_loot(host, data):
    os.makedirs("loot", exist_ok=True)
    filename = f"loot/ftp-{host.replace('.', '_')}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Loot saved: {filename}")

def try_login(host, port, user, passwd):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=5)
        banner_line = ftp.getwelcome()
        print(f"[+] FTP Banner: {banner_line}")
        ftp.login(user, passwd)
        print(f"[+] Login successful ({user}:{passwd})")
        return ftp, banner_line
    except ftplib.error_perm:
        print("[-] Login failed.")
        return None, None
    except Exception as e:
        print(f"[-] FTP connection failed: {e}")
        return None, None

def list_files(ftp):
    try:
        return ftp.nlst()
    except:
        return []

def find_writable_dirs(ftp):
    writable = []
    try:
        dirs = ftp.nlst()
        for d in dirs:
            try:
                ftp.cwd(d)
                testfile = "dharma_probe.txt"
                ftp.storbinary(f"STOR {testfile}", BytesIO(b"DharmaTest"))
                ftp.delete(testfile)
                writable.append(d)
                ftp.cwd("..")
            except:
                ftp.cwd("..")
                continue
    except:
        pass
    return writable

def detect_shells(ftp, writable_dirs):
    exts = ['.php', '.asp', '.jsp', '.pl', '.exe']
    shells = []
    for d in writable_dirs:
        try:
            ftp.cwd(d)
            for f in ftp.nlst():
                if any(f.lower().endswith(ext) for ext in exts):
                    shells.append(f"{d}/{f}")
            ftp.cwd("..")
        except:
            continue
    return shells

def test_upload(ftp, writable_dirs):
    for d in writable_dirs:
        try:
            ftp.cwd(d)
            testfile = "dharmatest_upload.txt"
            content = BytesIO(b"UploadVerify")
            ftp.storbinary(f"STOR {testfile}", content)
            ftp.delete(testfile)
            print(f"[+] Upload verified to {d}")
            return True
        except:
            continue
    return False

def detect_vulnerabilities(banner_text):
    vulns = []
    if not banner_text:
        return vulns
    if "vsFTPd 2.3.4" in banner_text:
        vulns.append("vsFTPd 2.3.4 - CVE-2011-2523 (Backdoor)")
    if "ProFTPD" in banner_text and "1.3.5" in banner_text:
        vulns.append("ProFTPD 1.3.5 - CVE-2015-3306 (mod_copy)")
    return vulns

def ftp_recon(host, port, user, passwd, verify_upload):
    result = {
        "target": host,
        "port": port,
        "user": user,
        "anonymous_login": (user == "anonymous"),
        "writable_dirs": [],
        "top_level_files": [],
        "shell_files": [],
        "upload_verified": False,
        "vulnerabilities": [],
        "banner": "",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    ftp, banner_text = try_login(host, port, user, passwd)
    if not ftp and user != "anonymous":
        print("[*] Falling back to anonymous login")
        ftp, banner_text = try_login(host, port, "anonymous", "anonymous@ftp")
        result["anonymous_login"] = True
        result["user"] = "anonymous"

    if not ftp:
        print("[-] FTP login ultimately failed. Exiting.")
        return

    result["banner"] = banner_text

    ftp_banner("Listing top-level files:")
    files = list_files(ftp)
    for f in files:
        print(f"    - {f}")
    result["top_level_files"] = files

    ftp_banner("Detecting writable directories:")
    writable = find_writable_dirs(ftp)
    for d in writable:
        print(f"    - Writable: {d}")
    result["writable_dirs"] = writable

    ftp_banner("Searching for shell files:")
    shells = detect_shells(ftp, writable)
    for s in shells:
        print(f"    - Shell detected: {s}")
    result["shell_files"] = shells

    if verify_upload and writable:
        ftp_banner("Testing upload to writable dir:")
        result["upload_verified"] = test_upload(ftp, writable)

    result["vulnerabilities"] = detect_vulnerabilities(banner_text)

    ftp.quit()
    save_loot(host, result)

    # Summary
    ftp_banner("Operator Summary:")
    print(f"    Login used: {result['user']}")
    print(f"    Writable dirs: {', '.join(writable) if writable else 'None'}")
    print(f"    Detected shells: {', '.join(shells) if shells else 'None'}")
    print(f"    Upload test: {'✔' if result['upload_verified'] else '✘'}")

    if result["vulnerabilities"]:
        ftp_banner("Known Vulnerabilities:")
        for v in result["vulnerabilities"]:
            print(f"    - {v}")

    print("\n[+] Suggested NSE:")
    print(f"    nmap -p21 {host} --script ftp-anon,ftp-user-enum")

    if writable:
        print("\n[+] Suggested Exploits:")
        print(f"    - Upload PHP shell to writable dir: {writable[0]}")
        print(f"    - Trigger via browser or LFI (if web is present)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Weaponized FTP recon tool for Dharma-Tools")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=21, help="FTP port (default 21)")
    parser.add_argument("--user", default="anonymous", help="FTP username")
    parser.add_argument("--password", dest="password", default="anonymous@ftp", help="FTP password")
    parser.add_argument("--verify-upload", action="store_true", help="Try uploading a test file to writable dir")
    args = parser.parse_args()

    ftp_recon(args.target, args.port, args.user, args.password, args.verify_upload)
