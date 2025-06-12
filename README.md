# 🔱 Dharma-Tools

**Dharma-Tools** is a curated red team and offensive security toolkit authored by **Braxton Bailey ([@Jimi421](https://github.com/Jimi421))**, designed to:

- 🚀 Automate enumeration, brute force, and post-exploitation tasks
- 🧪 Provide a clean lab testbed for safe tool validation
- 🎯 Focus on operator usability and modular scripts
- 🧠 Enhance Nmap with red team–oriented NSE scripts

This project is ideal for:

- Ethical hackers
- CTF players
- Adversary simulation teams
- Developers learning secure design through breakage

---

## 🧰 Toolkit Overview

| Directory        | Purpose                                      |
|------------------|----------------------------------------------|
| `nse/`           | Custom NSE scripts for Nmap (brute, enum)    |
| `payloads/`      | Web shells, reverse shells, post-ex tools    |
| `utils/`         | Uploaders, brute wrappers, wordlists         |
| `test-targets/`  | Local vulnerable services (Docker)           |
| `docs/`          | Script documentation & module notes          |

---

## 🔍 Featured NSE Scripts

| Script                  | Description                                          |
|-------------------------|------------------------------------------------------|
| `http-json-brute.nse`   | JSON-based login brute forcing for APIs             |
| `ftp-user-enum.nse`     | Detect valid FTP usernames using response codes     |
| `smb-anon-hunter.nse`   | Recursive SMB loot file discovery via guest access  |

See [`nse/README.md`](nse/README.md) for full argument breakdown and examples.

---

## 🧪 Local Lab: `test-targets/`

Test and validate your scripts using safe, Dockerized services:

| Folder       | Service        | Port | Description                             |
|--------------|----------------|------|-----------------------------------------|
| `flask-api/` | Flask API      | 5000 | API login testing for `http-json-brute` |
| `ftp-lab/`   | FTP Server     | 21   | Anonymous FTP enum for `ftp-user-enum`  |
| `smb-lab/`   | Samba Share    | 445  | Test `smb-anon-hunter` and file access  |

### 🔧 Quickstart

```bash
cd test-targets/flask-api && docker build -t flask-login-api .
cd ../ftp-lab && docker build -t ftp-lab .
cd ../smb-lab && docker build -t smb-lab .

docker run -d -p 5000:5000 flask-login-api
docker run -d -p 21:21 ftp-lab
docker run -d -p 445:445 smb-lab
⚙️ Payloads & Uploads
Dharma includes real-world test payloads for:

Web shells (payloads/web/)

Reverse shells (payloads/web/reverse_shell.php)

Upload via utils/ftp_uploader.py

Example upload:

bash
Copy
Edit
./utils/ftp_uploader.py 192.168.56.101 anonymous anonymous@example.com payloads/web/webshell.php
📦 Wordlists
Use these with NSE scripts or custom brute force:

bash
Copy
Edit
nmap -p21 <target> --script ./nse/ftp-user-enum.nse \
--script-args "userdb=utils/wordlists/usernames.txt"
🧠 Author
👤 Braxton Bailey
🔗 GitHub: @Jimi421

🛡️ Disclaimer
This toolkit is for educational and authorized testing only.

Never use Dharma-Tools on targets you do not own or lack explicit permission to test.

🔗 Contributions
Pull requests are welcome. If you want to submit new NSE scripts, payloads, or lab targets:

Use the structure and doc conventions shown in existing modules

Include a test target or describe reproduction steps

Keep scripts modular, with proper NSE metadata blocks

🔮 Roadmap
 ldap-user-enum.nse

 http-token-leak-check.nse

 rpc-null-audit.nse

 NSE automation launcher (auto-nse.py)

 Payload delivery module (smb_autopusher.py, http_dropper.py)

 MkDocs documentation site (docs/)

🧠 Weaponize knowledge.
💣 Automate access.
🔱 Build tools that last.

—
Dharma-Tools: Red Team Lab & Arsenal
