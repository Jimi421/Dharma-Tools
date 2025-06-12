# 🧪 Dharma Test Targets

This directory contains self-contained Dockerized services for safely testing Dharma NSE scripts and payloads.

## Available Targets

| Service     | Folder        | Port | Purpose                             |
|-------------|---------------|------|-------------------------------------|
| Flask API   | flask-api/    | 5000 | Test JSON login brute-forcing       |
| FTP Server  | ftp-lab/      | 21   | Test anonymous access and enum      |
| SMB Server  | smb-lab/      | 445  | Test share access, leaks, enum      |

---

## ⚠️ Warning

These services are **intentionally vulnerable**.  
Only run them on **isolated, non-internet-facing environments**.


