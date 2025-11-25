# backend/filter.py
import re
import logging

from .ml_engine import predict_multiclass, predict_text_label
from .config import ML_CONF_THRESHOLD

logger = logging.getLogger("backend.filter")

SQLI_RX = re.compile(r"(\bselect\b|\bdrop\b|\binsert\b|\bunion\b|\bupdate\b|\bdelete\b|--|\bOR\b\s+\d+=\d+)", re.I)
XSS_RX  = re.compile(r"(<script\b|onerror=|onload=|javascript:|<img\s+[^>]*src=)", re.I)


# -------------------------------------------------------------------
# SAFE WRAPPER FOR TEXT MODEL
# Prevents decide_route from crashing on bad ML output
# -------------------------------------------------------------------
def safe_predict_text_label(text):
    """
    Normalizes any return from predict_text_label(text)
    into (label, confidence). On any error, returns (None, 0.0)
    and logs what happened.
    """

    try:
        res = predict_text_label(text)
    except Exception as e:
        logger.exception("predict_text_label raised an exception")
        return None, 0.0

    # Case 1: model returned None
    if res is None:
        logger.warning("predict_text_label returned None for text=%s", text[:200])
        return None, 0.0

    # Case 2: tuple/list
    if isinstance(res, (tuple, list)):
        if len(res) == 2:
            label, conf = res
            try:
                conf = float(conf)
            except:
                conf = 0.0
            return label, conf

        if len(res) > 2:
            logger.warning("predict_text_label returned >2 elements: %r", res)
            try:
                label, conf = res[0], float(res[1])
            except:
                label, conf = None, 0.0
            return label, conf

    # Case 3: dict-like output
    if isinstance(res, dict):
        label = (
            res.get("label")
            or res.get("attack_type")
            or res.get("pred")
            or None
        )
        conf = (
            res.get("confidence")
            or res.get("prob")
            or res.get("score")
            or 0.0
        )
        try:
            conf = float(conf)
        except:
            conf = 0.0
        logger.info("predict_text_label returned dict -> %s, %s", label, conf)
        return label, conf

    # Unknown types
    logger.warning("predict_text_label returned unexpected type %s -> %r",
                   type(res), res)
    return None, 0.0


# -------------------------------------------------------------------
# MAIN DECISION ROUTER
# -------------------------------------------------------------------
def decide_route(payload_data):
    """
    Input: payload_data dict with keys: payload (text), features (optional dict), src_ip
    Output: decision dict with keys: route, reason, attack_type, confidence, probs, features
    """
    text = (payload_data.get("payload") or "")
    text_low = text.lower()

    # 1) Fast signature-based checks
    if SQLI_RX.search(text) or any(tok in text_low for tok in ("select ", "union ", "information_schema")):
        return {
            "route": "honeypot",
            "reason": "rule_match_sqli",
            "attack_type": "Web Attack - Sql Injection",
            "confidence": 0.99,
            "probs": None,
            "features": {}
        }

    if XSS_RX.search(text) or "<script" in text_low or "onerror=" in text_low:
        return {
            "route": "honeypot",
            "reason": "rule_match_xss",
            "attack_type": "Web Attack - XSS",
            "confidence": 0.99,
            "probs": None,
            "features": {}
        }

    # brute-force keyword check
    if any(k in text_low for k in ("password", "login attempt", "authentication failed", "bad credentials")):
        return {
            "route": "honeypot",
            "reason": "rule_match_bruteforce",
            "attack_type": "Brute Force",
            "confidence": 0.95,
            "probs": None,
            "features": {}
        }

    if any(k in text_low for k in ("nmap", "scan", "syn probe", "port scan")):
        return {
            "route": "honeypot",
            "reason": "rule_match_portscan",
            "attack_type": "PortScan",
            "confidence": 0.95,
            "probs": None,
            "features": {}
        }

    # 2) If numeric features are present, use ML multiclass model
    features = payload_data.get("features")
    if features:
        label, conf, probs = predict_multiclass(features)

        if label != "BENIGN" and conf >= ML_CONF_THRESHOLD:
            return {
                "route": "honeypot",
                "reason": "ml_detected",
                "attack_type": label,
                "confidence": conf,
                "probs": probs,
                "features": features
            }
        else:
            return {
                "route": "normal",
                "reason": "ml_benign" if label == "BENIGN" else "ml_low_conf",
                "attack_type": label,
                "confidence": conf,
                "probs": probs,
                "features": features
            }

    # 3) Text fallback model (safe wrapper)
    lbl, conf = safe_predict_text_label(text)

    if lbl and lbl != "BENIGN" and conf >= ML_CONF_THRESHOLD:
        return {
            "route": "honeypot",
            "reason": "text_model_detected",
            "attack_type": lbl,
            "confidence": conf,
            "probs": None,
            "features": {}
        }

    # default - allow traffic
    return {
        "route": "normal",
        "reason": "no_match",
        "attack_type": "BENIGN",
        "confidence": 0.0,
        "probs": None,
        "features": {}
    }
