# backend/honeypot_handlers.py
from flask import jsonify, render_template_string, request

# Very simple fake HTML page (make it look realistic)
FAKE_PAGE_HTML = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Products - Shop</title></head>
<body>
  <h1>Products</h1>
  <table border="1">
    <tr><th>ID</th><th>Name</th><th>Price</th></tr>
    <tr><td>1001</td><td>Widget A</td><td>$9.99</td></tr>
    <tr><td>1002</td><td>Gadget B</td><td>$19.99</td></tr>
  </table>
  <p><small>— data simulated by honeypot</small></p>
</body>
</html>
"""

def serve_fake_page():
    """
    Return a simple fake HTML page for web-based attacks.
    """
    return render_template_string(FAKE_PAGE_HTML), 200

def fake_db_response():
    """
    Return a fake JSON 'table dump' for SQLi probing attackers
    """
    rows = [
        {"id": 1001, "username": "alice", "email": "alice@example.com"},
        {"id": 1002, "username": "bob", "email": "bob@example.com"},
        {"id": 1003, "username": "carol", "email": "carol@example.com"}
    ]
    return jsonify({"rows": rows, "note": "simulated honeypot data"}), 200
