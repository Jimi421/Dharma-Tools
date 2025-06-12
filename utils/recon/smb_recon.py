#!/usr/bin/env python3
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, lsat, samr
import argparse, json, os, re
from datetime import datetime

COMMON_PIPES = ['lsarpc', 'samr', 'svcctl', 'netlogon', 'spoolss', 'browser']

def banner(text):
    print(f"\n[+] {text}")

def save_loot(host, data):
    os.makedirs("loot", exist_ok=True)
    filename = f"loot/smb-{host.replace('.', '_')}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Loot saved: {filename}")

def test_named_pipes(host):
    open_pipes = []
    for pipe in COMMON_PIPES:
        try:
            smb = SMBConnection(host, host, sess_port=445)
            smb.login('', '')
            smb.connectTree('IPC$')
            fid = smb.openFile('IPC$', f'\\{pipe}')
            open_pipes.append(pipe)
            smb.closeFile('IPC$', fid)
        except:
            continue
    return open_pipes

def get_domain_sid(host):
    try:
        rpctransport = transport.SMBTransport(host, 445, r'\lsarpc', '', '', '', '', '', False)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        policy = lsat.LsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES)['PolicyHandle']
        sid_info = lsat.LsarQueryInformationPolicy2(dce, policy, lsat.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        return sid_info['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
    except:
        return None

def bruteforce_users_via_sid(host, sid_base, start=500, stop=550):
    found_users = []
    try:
        rpctransport = transport.SMBTransport(host, 445, r'\samr', '', '', '', '', '', False)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        server_handle = samr.hSamrConnect(dce)['ServerHandle']
        domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)['Buffer']['Buffer']
        domain_name = domains[0]['Name']
        domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP, domain_name)['DomainHandle']

        for rid in range(start, stop):
            sid = f"{sid_base}-{rid}"
            try:
                name = samr.hSamrLookupIdsInDomain(dce, domain_handle, [rid])['Names'][0]['Name']
                found_users.append({'rid': rid, 'name': str(name)})
            except:
                continue
    except Exception as e:
        print(f"[-] RID brute failed: {e}")
    return found_users

def smb_recon(host, port=445):
    loot = {
        "target": host,
        "port": port,
        "shares": [],
        "users": [],
        "pipes": [],
        "system_info": {},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    try:
        smb = SMBConnection(host, host, sess_port=port, timeout=5)
        smb.login('', '')
        banner(f"Connected anonymously to SMB on {host}")
    except Exception as e:
        print(f"[-] Anonymous login failed: {e}")
        return

    try:
        loot["system_info"]["os"] = smb.getServerOS()
        loot["system_info"]["hostname"] = smb.getServerName()
        loot["system_info"]["domain"] = smb.getServerDomain()
        print(f"    Hostname: {loot['system_info']['hostname']}")
        print(f"    OS: {loot['system_info']['os']}")
    except:
        pass

    # Share enum
    banner("Enumerating shares:")
    try:
        shares = smb.listShares()
        for share in shares:
            name = share['shi1_netname'][:-1]
            access = "NO ACCESS"
            try:
                smb.listPath(name, '*')
                access = "READ"
                dummy = "dharma_temp.txt"
                fh = smb.createFile(name, f"\\{dummy}")
                smb.closeFile(name, fh)
                smb.deleteFile(name, f"\\{dummy}")
                access = "WRITE"
            except Exception as e:
                if "STATUS_ACCESS_DENIED" in str(e):
                    access = "NO ACCESS"
                elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    access = "READ"
            loot["shares"].append({"name": name, "access": access})
            print(f"    Share: {name} — Access: {access}")
    except Exception as e:
        print(f"[-] Share enumeration failed: {e}")

    # Pipe discovery
    banner("Enumerating named pipes:")
    pipes = test_named_pipes(host)
    loot["pipes"] = pipes
    for pipe in pipes:
        print(f"    Pipe open: {pipe}")

    # RID cycling
    banner("Enumerating users via RID cycling:")
    sid = get_domain_sid(host)
    if sid:
        print(f"    Domain SID: {sid}")
        users = bruteforce_users_via_sid(host, sid)
        for user in users:
            print(f"    RID {user['rid']}: {user['name']}")
        loot["users"] = users
    else:
        print("    Could not retrieve SID.")

    save_loot(host, loot)

    # Operator summary
    banner("Operator Summary")
    os_info = loot['system_info'].get("os", "").lower()
    if "windows" in os_info:
        print("    Target appears to be a Windows host.")
    if "samba" in os_info.lower():
        print("    Target is likely Samba/Linux.")

    if loot["shares"]:
        print("    Found shares:")
        for s in loot["shares"]:
            print(f"      - {s['name']} ({s['access']})")

    if loot["users"]:
        print(f"    Enumerated {len(loot['users'])} user(s) via RID cycling")

    if loot["pipes"]:
        print(f"    Open named pipes: {', '.join(loot['pipes'])}")

    print("\n[+] Suggested NSE Commands:")
    print(f"    nmap -p445 {host} --script smb-anon-hunter.nse")
    print(f"    nmap -p445 {host} --script smb-enum-shares,smb-enum-users")

    if any(s['access'] == 'WRITE' for s in loot['shares']):
        print("\n[+] Suggested Exploits:")
        print(f"    - Upload a reverse shell to a WRITEable share")
        print(f"    - Trigger via UNC path or scheduled task")
        print(f"    - Use smbclient //{host}/<writable> -N")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full-spectrum SMB recon for Dharma-Tools")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=445, help="SMB port (default 445)")
    args = parser.parse_args()

    smb_recon(args.target, args.port)

