# backend/config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env (only in local/dev)
# In Docker, env vars come from compose and override .env
load_dotenv()

def env(name, default=None, cast=str):
    """Unified env getter with type casting."""
    value = os.getenv(name, None)

    if value is None:
        return default

    if cast is bool:
        return str(value).lower() in ("1", "true", "yes", "on")

    try:
        return cast(value)
    except Exception:
        return value


# --------------------------------------------------------------------------------------
# ⚙️ GENERAL APP CONFIG
# --------------------------------------------------------------------------------------

HONEYPOT_BIND_HOST = env("HONEYPOT_BIND_HOST", "0.0.0.0")
HONEYPOT_BIND_PORT = env("HONEYPOT_BIND_PORT", 5000, int)

ML_CONF_THRESHOLD = env("ML_CONF_THRESHOLD", 0.65, float)
HONEYPOT_ENABLED = env("HONEYPOT_ENABLED", True, bool)

# --------------------------------------------------------------------------------------
# 🔐 SECURITY: ADMIN TOKEN FOR PROTECTED ENDPOINTS
# --------------------------------------------------------------------------------------
ADMIN_TOKEN = env("ADMIN_TOKEN", None)

if ADMIN_TOKEN is None:
    # Generate a secure fallback token *inside container only* (safe)
    ADMIN_TOKEN = "local-dev-token"
    print("⚠️ WARNING: ADMIN_TOKEN not set. Using default local token.")

# --------------------------------------------------------------------------------------
# 🚀 REDIS — USE DOCKER SERVICE NAME (not localhost)
# --------------------------------------------------------------------------------------
REDIS_URL = env("REDIS_URL", "redis://redis:6379/0")

# --------------------------------------------------------------------------------------
# 📜 LOGGING CONFIGURATION
# --------------------------------------------------------------------------------------

# store logs in mounted /data/logs inside container
DEFAULT_LOG_DIR = "/data/logs"

LOG_PATH = env("LOG_PATH", DEFAULT_LOG_DIR)

LOG_LEVEL = env("LOG_LEVEL", "INFO").upper()
