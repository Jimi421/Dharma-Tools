from flask import Flask, request, jsonify

app = Flask(__name__)

users = {
    "admin": "admin123",
    "user": "letmein"
}

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data: return jsonify({"error": "No input"}), 400
    u, p = data.get('username'), data.get('password')
    if users.get(u) == p:
        return jsonify({"token": "abc123"}), 200
    return jsonify({"error": "Unauthorized"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

