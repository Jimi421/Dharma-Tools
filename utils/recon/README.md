# 🔍 Recon Scripts

This directory contains recon utilities that identify exposed services, gather metadata, and generate loot files for Dharma’s automated exploitation modules.

Each script is designed to produce machine-readable output (`loot/*.json`) that powers the `auto-nse.py` and `auto-exploit.py` engines.

---

## 📌 Mission

Recon is the **entrypoint of the kill chain**. These scripts aim to:

- Detect open services (HTTP, FTP, SMB)
- Parse banners, endpoints, shares, login forms
- Write structured `.json` loot to the `loot/` directory
- Enable chained exploitation based on verified attack surfaces

---

## 📁 Script Requirements

Each script in this directory should:

- Take a `--target` or `--ip` argument
- Produce a loot file to:  
  `loot/<proto>-<ip>.json`

- Return a JSON structure like:

### Example: `loot/ftp-10_10_10_42.json`

```json
{
  "anonymous_login": true,
  "writable_dirs": ["uploads", "tmp"]
}
Example: loot/http-10_10_10_42.json
json
Copy
Edit
{
  "logins": [
    {
      "url": "/api/auth",
      "method": "form",
      "username_field": "user",
      "password_field": "pass"
    }
  ]
}
🔱 Recon Output Drives Exploitation
Protocol	Recon Script Output	Consumed By
FTP	anon access + writable dirs	auto-exploit.py
SMB	null session + share perms	auto-exploit.py
HTTP	login forms, endpoints	auto-nse.py, brute

✅ Included Scripts
bash
Copy
Edit
recon/
├── ftp_recon.py         # Detects anon login, writable shares
├── smb_recon.py         # Enumerates shares via null session
├── http_recon.py        # Looks for login endpoints, JSON forms
├── ...
🔧 Usage Example
bash
Copy
Edit
python3 recon/ftp_recon.py --target 10.10.10.42
Outputs:

bash
Copy
Edit
[+] FTP anonymous login successful
[+] Writable directory found: uploads/
[*] Loot written to loot/ftp-10_10_10_42.json
📁 Expected Output Structure
pgsql
Copy
Edit
loot/
├── ftp-10_10_10_42.json
├── smb-10_10_10_42.json
└── http-10_10_10_42.json
These files feed directly into Dharma’s auto-nse.py and auto-exploit.py.

🧠 Best Practices
Ensure every recon script validates service reachability

Use consistent JSON schemas (see examples above)

Do not overwrite loot unless explicitly instructed

Include minimal passive detection to stay stealthy (where appropriate)

📦 Dependencies
Python 3.x

impacket (for SMB)

requests (for HTTP)

ftplib (built-in)

Recon is reality. Everything else is just guesses.
