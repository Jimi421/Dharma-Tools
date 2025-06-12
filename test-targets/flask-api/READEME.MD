# 🧪 Flask API - JSON Login Target

This is a deliberately vulnerable JSON login endpoint designed for testing scripts like:

- `http-json-brute.nse`
- Hydra or ffuf brute-force attacks
- API token parsing logic

---

## 🔧 Usage

### ▶️ Build & Run
```bash
docker build -t flask-login-api .
docker run -p 5000:5000 flask-login-api
📍 Endpoint
bash
Copy
Edit
POST http://localhost:5000/api/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
✅ Valid Users
Username	Password
admin	admin123
user	letmein
root	toor

🔎 Test With NSE Script
bash
Copy
Edit
nmap -p5000 127.0.0.1 --script ./nse/http-json-brute.nse --script-args \
"http-json-brute.path=/api/login,userdb=utils/wordlists/usernames.txt,passdb=utils/wordlists/passwords.txt"
⚠️ Notes
No rate limiting

No auth token required

Success is detected by "token" key in the response
