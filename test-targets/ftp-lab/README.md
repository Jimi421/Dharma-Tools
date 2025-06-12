# 🧪 FTP-Lab

This is an anonymous FTP server configured with no authentication and minimal security. Intended for:

- Anonymous access enum (`ftp-user-enum.nse`)
- Listing `flag.txt` in home directory
- Upload/download testing (future)

---

## 🔧 Usage

### ▶️ Build & Run

```bash
docker build -t ftp-lab .
docker run -p 21:21 ftp-lab
📍 Connection
makefile
Copy
Edit
ftp localhost 21
Username: anonymous
Password: (blank or anything)
📁 Files Available
Path	Description
/flag.txt	Example loot file

🔎 NSE Example
bash
Copy
Edit
nmap -p21 127.0.0.1 --script ./nse/ftp-user-enum.nse
⚠️ Notes
No real password enforcement

No upload enabled

No SSL/TLS
