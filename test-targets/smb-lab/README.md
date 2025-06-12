# 🧪 SMB-Lab

A vulnerable Samba server exposing world-readable shares. Intended for:

- `smb-anon-hunter.nse` testing
- File exfiltration
- Unauthorized access checks

---

## 🔧 Usage

### ▶️ Build & Run

```bash
docker build -t smb-lab .
docker run -p 445:445 smb-lab
📁 Shared Directory
Share Name	Path
public	/srv/smb/public

Contents:

creds.env

keys/id_rsa

🔎 Test Example
bash
Copy
Edit
nmap -p445 127.0.0.1 --script ./nse/smb-anon-hunter.nse
⚠️ Notes
Guest access is allowed (no username/password required)

This lab is intentionally insecure

yaml
Copy
Edit

---

# ✅ Top-Level `test-targets/README.md`

```markdown
# 🧪 Dharma Test Targets

This directory contains all local vulnerable environments used for testing NSE scripts and red team payloads from the Dharma-Tools project.

---

## 📂 Services

| Folder       | Service        | Port | Purpose                              |
|--------------|----------------|------|--------------------------------------|
| `flask-api/` | JSON API Login | 5000 | Used for API brute-force testing     |
| `ftp-lab/`   | FTP Server     | 21   | Tests anonymous FTP enum/exfil       |
| `smb-lab/`   | SMB Server     | 445  | Share enum and sensitive file leaks  |

---

## 🔧 Running All Targets

```bash
cd test-targets/flask-api && docker build -t flask-login-api .
cd test-targets/ftp-lab && docker build -t ftp-lab .
cd test-targets/smb-lab && docker build -t smb-lab .

docker run -d -p 5000:5000 flask-login-api
docker run -d -p 21:21 ftp-lab
docker run -d -p 445:445 smb-lab
🧠 Best Practices
Run on isolated virtual networks

Use with nmap, Burp Suite, Hydra, or custom brute tools

Document which NSE scripts are validated with each target

yaml
Copy
Edit

