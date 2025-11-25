# backend/run_server.py
from .app import app
if __name__ == "__main__":
    # fallback dev start if run directly
    app.run(host="0.0.0.0", port=5000, debug=False)
