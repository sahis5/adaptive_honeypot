# backend/decision_engine.py
import numpy as np
import os
import json
import time
import threading
import logging
from collections import defaultdict

# hooks to other modules in your project
from .rl_agent import choose_action as rl_choose_action  # returns action string or None
from .redis_bucket import consume_token                      # Redis token-bucket
from .metrics import observe_request                        # metrics recorder

logger = logging.getLogger(__name__)

# persistent q-table path
Q_PATH = os.path.join(os.path.dirname(__file__), "q_table.json")

# canonical list of actions the engine uses
ACTIONS = [
    "normal",            # no special handling
    "redirect_honeypot", # redirect attacker to honeypot page/api
    "fake_data",         # return fabricated/non-sensitive responses
    "tarpit_slowdown",   # slow response/tarpit behavior
    "block",             # block/request denial
    "challenge",         # challenge (captcha/2FA)
]

# small discrete state mapping used for Q-table (demo)
STATE_MAP = {
    "UNKNOWN": 0,
    "SQLI": 1,
    "BRUTE_FORCE": 2,
    "SCAN": 3,
    "OTHER": 4
}

# local token-bucket fallback (only used if redis unavailable)
_local_buckets = defaultdict(lambda: {"tokens": 5.0, "last": time.time()})
_local_lock = threading.Lock()

def _load_q():
    if os.path.exists(Q_PATH):
        try:
            with open(Q_PATH, "r") as f:
                arr = json.load(f)
            return np.array(arr)
        except Exception:
            logger.exception("Failed to load q table, recreating.")
    q = np.zeros((len(STATE_MAP), len(ACTIONS)))
    try:
        with open(Q_PATH, "w") as f:
            json.dump(q.tolist(), f)
    except Exception:
        logger.exception("Could not write initial q table")
    return q

def _save_q(q):
    try:
        with open(Q_PATH, "w") as f:
            json.dump(q.tolist(), f)
    except Exception:
        logger.exception("Failed to save q table")

Q = _load_q()

def update_q(state_name, action_name, reward, next_state_name, alpha=0.1, gamma=0.9):
    """Simple tabular Q update; action_name must be in ACTIONS."""
    try:
        s = STATE_MAP.get(state_name, 0)
        a = ACTIONS.index(action_name)
        ns = STATE_MAP.get(next_state_name, 0)
        q_val = Q[s][a]
        Q[s][a] = q_val + alpha * (reward + gamma * np.max(Q[ns]) - q_val)
        _save_q(Q)
    except ValueError:
        logger.exception("update_q: unknown action '%s'", action_name)
    except Exception:
        logger.exception("update_q failed")

def _fallback_choose_action(attack_label):
    """Deterministic heuristic mapping when RL agent returns None."""
    if not attack_label:
        return "normal"
    a = str(attack_label).upper()
    if "SQL" in a or "SQL INJECTION" in a or "SQLI" in a:
        return "redirect_honeypot"
    if "BRUTE" in a or "BRUTE FORCE" in a or "PASSWORD" in a or "SSH" in a:
        return "tarpit_slowdown"
    if "XSS" in a or "CROSS SITE" in a or "CROSS-SITE" in a:
        return "fake_data"
    if "PORTSCAN" in a or "DDOS" in a or "DOS" in a:
        return "block"
    if "BOT" in a or "SCRAPER" in a:
        return "challenge"
    return "normal"

def choose_action(attack_label):
    """
    Primary action chooser. Attempts RL agent first, then falls back.
    Returns an action string present in ACTIONS.
    """
    try:
        action = None
        try:
            action = rl_choose_action(attack_label)
        except Exception:
            # RL agent may not be present or raise - ignore and continue
            logger.debug("rl_choose_action failed or not available")
        if action:
            # sanitize: map RL output to allowed actions if needed
            if action not in ACTIONS:
                # if RL returned a heuristic name, try to map
                mapped = _fallback_choose_action(action)
                return mapped if mapped in ACTIONS else "normal"
            return action
    except Exception:
        logger.exception("choose_action RL branch failed")

    # fallback deterministic mapping
    return _fallback_choose_action(attack_label)

def _consume_token_redis_fallback(key, capacity=5, refill_rate=0.2):
    """
    Try redis consume_token; if redis not available, use in-memory bucket.
    Returns integer >=0 (remaining tokens) or -1 if throttle.
    """
    try:
        res = consume_token(key, capacity=capacity, refill_rate=refill_rate)
        # consume_token should return int or -1; handle string numbers
        try:
            return int(res)
        except Exception:
            return res
    except Exception:
        # fallback to local token bucket
        with _local_lock:
            b = _local_buckets[key]
            now = time.time()
            elapsed = now - b["last"]
            b["tokens"] = min(float(capacity), b["tokens"] + elapsed * float(refill_rate))
            b["last"] = now
            if b["tokens"] >= 1.0:
                b["tokens"] -= 1.0
                return int(b["tokens"])
            else:
                return -1

def perform_action(action_name, src_ip, request_context=None):
    """
    Decide *metadata* for the requested action. This is non-blocking;
    the caller (middleware / reverse-proxy / app) enforces the action:
      - redirect_honeypot -> redirect attacker to URL
      - fake_data -> serve synthetic content from honeypot handler
      - tarpit_slowdown -> middleware should sleep for delay_ms (or return chunked slow response)
      - block -> return 403
      - challenge -> return challenge (e.g. 401/402+captcha)
      - normal -> do nothing
    Returns a dict describing the action.
    """
    start = time.time()
    action_result = {"action": action_name}

    try:
        if action_name in ("tarpit_slowdown", "rate_limit", "delay"):
            # rate-limit via token bucket (Redis preferred)
            capacity = 5
            refill_rate = 0.1
            tokens_left = _consume_token_redis_fallback(src_ip, capacity=capacity, refill_rate=refill_rate)
            if isinstance(tokens_left, int) and tokens_left < 0:
                action_result["action"] = "throttled"
                action_result["status"] = 429
                action_result["delay_ms"] = 2000
            else:
                action_result["tokens_left"] = int(tokens_left) if isinstance(tokens_left, (int, float)) else None
                action_result["delay_ms"] = 3000 if action_name == "tarpit_slowdown" else 500

        elif action_name == "redirect_honeypot":
            action_result["url"] = "/honeypot/fakedb"
            action_result["action"] = "redirect"

        elif action_name == "fake_data":
            # metadata: nothing heavy here, middleware should call /honeypot endpoint or provide fake response
            action_result["fake"] = True

        elif action_name == "block":
            action_result["status"] = 403

        elif action_name == "challenge":
            action_result["status"] = 401
            action_result["challenge"] = "captcha"

        else:
            action_result["action"] = "normal"

    except Exception as e:
        logger.exception("perform_action error: %s", e)
        action_result = {"action": "normal"}

    # metrics
    elapsed = time.time() - start
    route = "honeypot" if action_result.get("action") != "normal" else "normal"
    try:
        observe_request(route, action_result.get("action", "none"), elapsed)
    except Exception:
        logger.debug("metrics observe_request failed")

    return action_result
