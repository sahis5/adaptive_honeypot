# backend/app.py
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import time
import os

# internal modules
from .logger import log_event, read_last
from .filter import decide_route
from .decision_engine import choose_action, perform_action, update_q
from .honeypot_handlers import serve_fake_page, fake_db_response
from .rl_agent import update as rl_update

# config, logging, auth
from .logging_config import setup_logging
from .config import (
    ADMIN_TOKEN,
    LOG_PATH,
    HONEYPOT_ENABLED,
    ML_CONF_THRESHOLD,
    HONEYPOT_BIND_HOST,
    HONEYPOT_BIND_PORT,
)
from .auth import require_admin
from .metrics import metrics_response
# optional ml reload (if ml_engine exposes reload_models)
try:
    from .ml_engine import reload_models
except Exception:
    reload_models = None

app = Flask(__name__)

# set up logging early
setup_logging()

# enable CORS after logging is configured
CORS(app)

# initialize runtime config from environment (but still editable via /config)
_app_config = {
    "ml_conf_threshold": ML_CONF_THRESHOLD if ML_CONF_THRESHOLD is not None else 0.65,
    "honeypot_enabled": bool(HONEYPOT_ENABLED),
}

app.logger.info("Adaptive Honeypot starting", extra={"config": _app_config})


@app.route("/config", methods=["GET", "POST"])
def config_handler():
    global _app_config
    if request.method == "GET":
        return jsonify(_app_config)
    # POST -> update keys provided in JSON
    try:
        data = request.get_json(force=True)
        for k, v in data.items():
            if k in _app_config:
                _app_config[k] = v
        app.logger.info("Config updated via API", extra={"new_config": _app_config})
        return jsonify({"status": "ok", "config": _app_config})
    except Exception as e:
        app.logger.exception("config_handler error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/toggle_honeypot", methods=["POST"])
def toggle_honeypot():
    global _app_config
    try:
        data = request.get_json(force=True)
        if "enabled" in data:
            _app_config["honeypot_enabled"] = bool(data["enabled"])
            app.logger.info("Honeypot toggled", extra={"enabled": _app_config["honeypot_enabled"]})
            return jsonify({"status": "ok", "honeypot_enabled": _app_config["honeypot_enabled"]})
        return jsonify({"status": "error", "error": "missing 'enabled'"}), 400
    except Exception as e:
        app.logger.exception("toggle_honeypot error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/reload_models", methods=["POST"])
@require_admin
def http_reload_models():
    """
    Hot-reload ML artifacts from external model folder or bundled assets.
    Safe to call at runtime (if ml_engine supports it). Protected by admin token.
    """
    if reload_models is None:
        return jsonify({"status": "error", "error": "reload_models not available"}), 501
    try:
        reload_models()
        app.logger.info("Models reloaded via API")
        return jsonify({"status": "ok", "message": "models reloaded"}), 200
    except Exception as e:
        app.logger.exception("reload_models failed")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route('/')
def index():
    return "Adaptive Honeypot Backend Running"


@app.route('/simulate_traffic', methods=['POST'])
def simulate_traffic():
    """
    Expect JSON:
    { "src_ip": "1.2.3.4", "payload": "..." , "features": {...} (optional) }
    Returns:
      {
        "route": "normal"|"honeypot",
        "decision": { ... full decision dict returned by decide_route ... },
        "action_result": { ... suggested action metadata ... }
      }
    """
    data = request.get_json(force=True) or {}

    # call routing logic
    try:
        decision = decide_route(data)
    except Exception as e:
        app.logger.exception("decide_route error")
        decision = {
            "route": "normal",
            "reason": "decide_route_error",
            "attack_type": None,
            "confidence": 0.0,
            "probs": None,
            "features": {},
            "ml_error": str(e)
        }

    # log incoming event with decision
    try:
        src = data.get('src_ip', request.remote_addr)
        log_event({
            "event": "incoming",
            "src_ip": src,
            "payload": data.get('payload'),
            "decision": decision,
            "ts": time.time()
        })
    except Exception:
        app.logger.exception("Failed to log incoming event")

    # If honeypot disabled globally via config/env or API, override decision to normal
    if not _app_config.get("honeypot_enabled", True):
        decision_overridden = dict(decision) if isinstance(decision, dict) else {}
        decision_overridden['route'] = 'normal'
        decision_overridden['reason'] = 'honeypot_disabled'
        return jsonify({"route": "normal", "decision": decision_overridden, "action_result": {"action": "normal"}}), 200

    # If the decision is to route to honeypot, call decision engine and log action
    if decision.get('route') == 'honeypot':
        try:
            # choose a state name heuristic from attack_type or payload
            state_name = "UNKNOWN"
            attack_type = decision.get('attack_type') or decision.get('ml_pred') or decision.get('attack') or decision.get('reason')
            payload = (data.get('payload') or '')
            if attack_type:
                if isinstance(attack_type, str) and "sql" in attack_type.lower():
                    state_name = "SQLI"
                else:
                    # normalize to uppercase short label if possible
                    state_name = str(attack_type).upper()
            elif "select" in payload.lower():
                state_name = "SQLI"

            # choose action and the action metadata (non-blocking)
            action_name = choose_action(state_name)
            action_result = perform_action(action_name, data.get('src_ip', request.remote_addr), request_context=data)

            # Log honeypot action event
            try:
                log_event({
                    "event": "honeypot_action",
                    "src_ip": data.get('src_ip', request.remote_addr),
                    "action": action_name,
                    "action_result": action_result,
                    "state": state_name,
                    "ts": time.time()
                })
            except Exception:
                app.logger.exception("Failed to log honeypot_action")

            # Return decision plus suggested action metadata
            response = {"route": "honeypot", "decision": decision, "action_result": action_result}
            return jsonify(response), 200
        except Exception as e:
            app.logger.exception("Error during honeypot action")
            return jsonify({"route": decision.get("route"), "decision": decision, "error": str(e)}), 200
    else:
        # normal route — return decision (no action)
        return jsonify({"route": decision.get("route"), "decision": decision, "action_result": {"action": "normal"}}), 200


# Honeypot endpoints — attacker-facing pages / APIs
@app.route('/honeypot', methods=['GET', 'POST'])
def honeypot_page():
    """
    Simple honeypot page. Real attackers may be redirected here.
    """
    try:
        return serve_fake_page()
    except Exception:
        app.logger.exception("serve_fake_page failed")
        return ("", 500)

@app.route("/metrics")
def metrics():
    return metrics_response()
@app.route('/honeypot/fakedb', methods=['GET', 'POST'])
def honeypot_fakedb():
    """
    Fake DB endpoint for SQLi attackers (returns simulated rows).
    """
    try:
        return fake_db_response()
    except Exception:
        app.logger.exception("fake_db_response failed")
        return jsonify({"error": "internal"}), 500


# Lightweight reward/update endpoint for honeypot interactions (optional)
@app.route('/honeypot/interaction', methods=['POST'])
def honeypot_interaction():
    """
    Called by a honeypot page when an interaction occurs (e.g., attacker submitted an injected query).
    Accepts JSON: { src_ip, payload, detected_state (e.g. 'SQLI'), action_taken }
    This endpoint updates the Q-table / learning agent (if present).
    """
    data = request.get_json(force=True) or {}
    src = data.get('src_ip', request.remote_addr)
    payload = data.get('payload', "")
    detected_state = data.get('detected_state', "UNKNOWN")
    action_taken = data.get('action_taken', None)

    # for demo: assign a simple reward heuristic
    reward = 0
    try:
        if detected_state and "SQL" in str(detected_state).upper() and action_taken in ("redirect_honeypot", "fake_data"):
            reward = 1

        # call update_q if available (legacy Q update / other learning)
        try:
            update_q(detected_state, action_taken, reward, detected_state)
        except Exception:
            app.logger.exception("update_q failed")

        # log interaction
        log_event({"event": "honeypot_interaction", "src_ip": src, "payload": payload, "action": action_taken, "reward": reward, "ts": time.time()})
    except Exception:
        app.logger.exception("honeypot_interaction handling failed")

    # RL agent update (separate; safe to fail)
    try:
        rl_update(detected_state, action_taken, reward, detected_state)  # simple next_state same as state for demo
    except Exception:
        app.logger.exception("rl_update failed")

    return jsonify({"status": "ok", "reward": reward}), 200


@app.route('/logs', methods=['GET'])
def logs():
    rows = read_last(200)
    return jsonify(rows)


@app.route('/debug/status', methods=['GET'])
@require_admin
def debug_status():
    # returns model paths, q_table presence and last events count
    try:
        from .model_loader import external_models_dir, get_model_path
    except Exception:
        external_models_dir = lambda: "unknown"
        get_model_path = lambda f: f"{f} (no model_loader)"
    # Q table file
    qdir = external_models_dir()
    qfile = os.path.join(qdir, "q_table.pkl")
    files = []
    if os.path.exists(qdir):
        files = [f for f in os.listdir(qdir)]
    # quick tail of log file if present (logger stores events in backend/logs.jsonl maybe)
    try:
        logs = read_last(20)
    except Exception:
        logs = []
    return jsonify({
        "external_models_dir": qdir,
        "q_table_exists": os.path.exists(qfile),
        "models_list": files,
        "recent_logs": logs[-10:]
    })


if __name__ == "__main__":
    # start app using env-configured host/port (configured via backend/config.py)
    app.logger.info("Starting Adaptive Honeypot HTTP server",
                    extra={"host": HONEYPOT_BIND_HOST, "port": HONEYPOT_BIND_PORT})
    app.run(host=HONEYPOT_BIND_HOST or "0.0.0.0", port=HONEYPOT_BIND_PORT or 5000, debug=False)
