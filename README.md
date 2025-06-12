# 🔱 Dharma-Tools

**Dharma** is a modular, safe-handoff red team toolkit designed for controlled enumeration, bruteforcing, exploitation, and shell delivery. Built for offensive security professionals who need surgical control and audit-friendly workflows.

---

## ✨ Features

- 🔍 Passive and active recon modules
- 🔐 HTTP brute-forcing with layered wordlist support
- 🧪 Curated and custom NSE scripts (SMB, HTTP, FTP)
- 📦 Payloads for Linux and Windows
- 🧠 Safe-handoff orchestration via `dharma.py`
- 📂 Organized loot collection with JSON output
- 🧰 Designed for extensibility and ethical automation

---

## 📁 Directory Structure

dharma-tools/
├── dharma.py # 🔱 Orchestrator script (safe handoffs)
├── utils/
│ ├── recon/ # Passive recon (http_recon.py)
│ ├── bruteforce/ # Brute-force modules (http_brute.py)
│ ├── auto-nse.py # NSE launcher with script args
│ └── auto-exploit.py # Exploit launcher (manual approval)
├── nse/ # Custom NSE scripts (SMB, HTTP, FTP)
├── wordlists/ # Usernames, passwords, combo lists
├── payloads/ # Shells, droppers, macros (Linux/Win)
├── test-targets/ # Local Docker targets for testing
├── loot/ # JSON loot from recon/brute modules
├── LICENSE
└── README.md


---

## 🔱 Orchestration: `dharma.py`

The `dharma.py` orchestrator guides you through each phase:

python3 dharma.py --target http://10.10.10.42

yaml
Copy
Edit

You will be prompted to:

1. 🔍 Run recon (e.g. find login forms)
2. 🔐 Review loot and optionally brute-force creds
3. 📜 Launch NSE scripts based on findings
4. 💥 Trigger safe exploit modules

All actions require human confirmation — no blind execution.

---

## 🔧 Components

### [`http_recon.py`](utils/recon/http_recon.py)
- Scans for login paths
- Parses login fields
- Saves loot for chaining into brute-force

### [`http_brute.py`](utils/bruteforce/http_brute.py)
- Supports `--level fast|full|breach`
- Accepts custom user/password lists
- Handles `form` or `json` login types

### [`auto-nse.py`](utils/auto-nse.py)
- Runs targeted Nmap scripts
- Automatically loads correct NSEs for protocols (SMB, HTTP, FTP)

### [`auto-exploit.py`](utils/auto-exploit.py)
- Interactive or guided use of found CVEs or service-level exploits

---

## 🔐 Safe Handoff Philosophy

Dharma will never:

- Automatically exploit targets without consent
- Deliver shells blindly
- Skip user review of loot or prompts

It enforces **red team rules of engagement** and supports **auditability**.

---

## 📦 Payloads

Stored in [`payloads/`](payloads/) and include:

- `linux/bash_reverse.sh`
- `linux/payload_root.c`
- `windows/powershell_reverse.ps1`
- `windows/dns_exfil.ps1`
- Obfuscated macros, shellcode launchers

---

## 📚 Wordlists

Included in [`wordlists/`](wordlists/):

- `usernames.txt`
- `passwords.txt` (top 10k)
- `passwords-big.txt` (RockYou-style)
- `ftp-users.txt`

💡 Compatible with `--userdb`, `--passdb` on brute modules.

---

## 🧪 NSE Scripts

Stored in [`nse/`](nse/), including:

- `http-json-brute.nse`
- `ftp-user-enum.nse`
- `smb-anon-hunter.nse`

Use with:

```bash
nmap -p 21 --script ./nse/ftp-user-enum.nse --script-args userdb=wordlists/ftp-users.txt
📌 Status
Module	Status
http_recon.py	✅ Stable
http_brute.py	✅ Stable
dharma.py	✅ Safe Orchestration
NSE scripts	✅ Curated & custom
Auto NSE/Exploit	⚙️ Extensible
Payloads	✅ Verified
Shell catching	🔜 Manual

🔭 Coming Soon
🧪 verify_creds.py

📊 loot_report.py HTML/Markdown generator

☁️ Remote test lab bootstrapping (via Docker)

👁️ Visual recon diff (compare scans over time)

📜 License
MIT License. Use responsibly, for ethical purposes, and only where authorized.

🧠 Author
Braxton Bailey (@Jimi421)
Built with 🔱 for red teamers, by a red teamer.


