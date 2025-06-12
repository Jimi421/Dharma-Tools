# 🧠 Dharma-Tools NSE Scripts

This directory contains custom [Nmap Scripting Engine (NSE)](https://nmap.org/book/nse.html) modules for offensive security, red teaming, and exploit research.

These scripts extend Nmap’s capabilities with:

- 🎯 Targeted brute force and auth testing
- 🔐 Anonymous enumeration and file hunting
- 🕵️ Passive recon and banner analysis
- ⚙️ Script-args for modular, operator-friendly workflows

> Scripts tested against services in `test-targets/` Docker labs and designed for **real-world red team use**.

---

## 🔍 Script Index

| Script                  | Purpose                                                  |
|-------------------------|----------------------------------------------------------|
| `http-json-brute.nse`   | Brute force JSON login endpoints                         |
| `smb-anon-hunter.nse`   | Loot discovery in anonymous SMB shares (recursive)       |
| `ftp-user-enum.nse`     | Detect valid FTP users via response codes & timing       |

---

## ✅ Script Usage Overview

```bash
nmap -p <port> <target> --script ./nse/<script>.nse --script-args <args>
🔸 http-json-brute.nse
Brute-force API logins that accept JSON POST bodies.

Args
Arg	Description
path	Target login endpoint (e.g. /api/login)
username_field	JSON field for username
password_field	JSON field for password
userdb, passdb	Files for usernames/passwords
success_regex	Regex that detects successful login

Example
bash
Copy
Edit
nmap -p443 <target> --script ./nse/http-json-brute.nse \
--script-args "http-json-brute.path=/api/login,http-json-brute.username_field=user,http-json-brute.password_field=pass,userdb=users.txt,passdb=pass.txt"
🔸 smb-anon-hunter.nse (v2)
Performs recursive enumeration of SMB shares with anonymous access to identify exposed secrets, config files, keys, and more.

🔥 Key Features
🔁 Recursive directory walk (depth control)

🔍 Loot patterns match .env, id_rsa, .key, etc.

🔐 Detects writable shares

⚙️ User-defined loot patterns via script args

📏 Outputs file size and mtime metadata

Args
Arg	Description
smb-anon-hunter.depth	Max recursion depth (default: 3)
smb-anon-hunter.patterns	Comma-separated file regexes (e.g. %.key$,id_rsa$)
smb-anon-hunter.verbose	Show all shares, even if no loot found

Example
bash
Copy
Edit
nmap -p445 192.168.56.101 --script ./nse/smb-anon-hunter.nse \
--script-args "smb-anon-hunter.depth=4,smb-anon-hunter.patterns=%.env$,id_rsa$,%.conf$"
🔸 ftp-user-enum.nse (v2)
Attempts to enumerate valid FTP usernames by:

🧠 Detecting 331 vs 530 FTP response codes

⏱️ Optionally using timing analysis fallback

📜 Supporting passive mode (just fetch banner)

🔍 Verbose logging for all attempts

Args
Arg	Description
userdb	Path to usernames wordlist
ftp-user-enum.verbose	Show all results, not just valid hits
ftp-user-enum.passive	Skip brute force, just grab banner

Example (active mode)
bash
Copy
Edit
nmap -p21 <target> --script ./nse/ftp-user-enum.nse \
--script-args "userdb=utils/wordlists/users.txt"
Example (passive only)
bash
Copy
Edit
nmap -p21 <target> --script ./nse/ftp-user-enum.nse \
--script-args "ftp-user-enum.passive=true"
🧪 Testing with test-targets/
Each NSE script is validated against local services built in test-targets/:

NSE Script	Test Target Folder	Docker Port
http-json-brute	flask-api/	5000
ftp-user-enum	ftp-lab/	21
smb-anon-hunter	smb-lab/	445

To start all labs:

bash
Copy
Edit
docker-compose up --build
📜 Contributing
Keep code modular and documented with full NSE doc blocks

Prefer standard Nmap libs (smb, unpwdb, ftp, stdnse)

Validate against test targets before PR

Submit scripts to nse/, and document args/output here

⚠️ Legal Disclaimer
These scripts are for authorized engagements only.

Never use Dharma-Tools scripts on systems you don’t own or lack legal permission to test.

🧠 Coming Soon
Script	Purpose
ldap-user-enum.nse	Detect valid LDAP users via bind response
vnc-auth-bypass.nse	Check for null or weak VNC credentials
mssql-xpcmdshell-check	Discover command exec via xp_cmdshell
http-token-leak-check	Scan for API keys in headers/params

🔗 Resources
Nmap NSE Book: https://nmap.org/book/nse.html

NSE Dev Guide: https://nmap.org/nsedoc/

Dharma Payloads: ../payloads/

🧠 Stay stealthy. Hunt precisely.
💣 Build tools that validate access, loot quietly, and scale offensively.

—
Dharma-Tools NSE Arsenal

yaml
Copy
Edit

---

# ✅ File Path

```bash
Dharma-Tools/
└── nse/
    ├── README.md   ← THIS FILE
    ├── smb-anon-hunter.nse
    ├── ftp-user-enum.nse
    └── http-json-brute.nse
