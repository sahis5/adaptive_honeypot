# examples/flask_demo/app.py
from flask import Flask, request, redirect, jsonify
import requests, time, os

HONEYPOT_URL = os.environ.get("HONEYPOT_URL", "http://127.0.0.1:5000/simulate_traffic")
HONEYPOT_TIMEOUT = float(os.environ.get("HONEYPOT_TIMEOUT", "0.25"))

app = Flask(__name__)

def call_honeypot(payload, src_ip):
    try:
        r = requests.post(HONEYPOT_URL, json={"src_ip": src_ip, "payload": payload}, timeout=HONEYPOT_TIMEOUT)
        return r.json()
    except Exception:
        return {"route": "normal", "action_result": {"action": "normal"}}

@app.before_request
def hp_middleware():
    # skip static & health
    if request.path.startswith("/static") or request.path.startswith("/health"):
        return None
    payload = request.get_data(as_text=True) or request.path
    src = request.remote_addr
    resp = call_honeypot(payload, src)
    ar = resp.get("action_result", {}) or {}
    act = ar.get("action")
    if act == "redirect":
        return redirect(ar.get("url", "/honeypot"))
    if act == "tarpit":
        delay = ar.get("delay_ms", 200)
        time.sleep(delay / 1000.0)
        return None
    if act == "block":
        return ("Forbidden", 403)
    return None

@app.route('/')
def index():
    return "Hello from Demo App"

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        return "Login attempt received"
    return '''
      <form method="post">
        <input name="username"/><input name="password"/><input type="submit"/>
      </form>
    '''

@app.route('/health')
def health():
    return jsonify({"status":"ok"})

if __name__ == "__main__":
    app.run(port=8000, debug=True)
