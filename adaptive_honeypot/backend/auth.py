# backend/auth.py
from functools import wraps
from flask import request, jsonify
from .config import ADMIN_TOKEN

def require_admin(f):
    @wraps(f)
    def inner(*args, **kwargs):
        # check Authorization header (Bearer) or token query param
        token = None
        auth_h = request.headers.get("Authorization")
        if auth_h:
            if auth_h.lower().startswith("bearer "):
                token = auth_h.split(None, 1)[1]
            else:
                token = auth_h
        if not token:
            token = request.args.get("token")
        # allow JSON body field admin_token for convenience in some clients
        if not token and request.is_json:
            try:
                token = request.get_json(silent=True).get("admin_token")
            except Exception:
                token = None
        if token != ADMIN_TOKEN:
            return jsonify({"status":"error","error":"unauthorized"}), 401
        return f(*args, **kwargs)
    return inner
