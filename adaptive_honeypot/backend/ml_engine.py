# backend/ml_engine.py
"""
Simple ML engine wrapper for the adaptive honeypot.
Provides:
 - predict_multiclass(features_dict) -> { attack_type, confidence, probs, features, reason }
 - predict_text_label(text) -> short_label (like "Web Attack - Sql Injection") or None

This module will try to load saved models via model_loader.get_model_path and joblib.
If models are missing/unreadable it falls back to simple rule-based detection for text (SQLi/XSS).
"""

import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# try to import model loader utilities if present
try:
    from .model_loader import get_model_path, external_models_dir
    import joblib
    HAS_JOBLIB = True
except Exception:
    get_model_path = None
    external_models_dir = lambda: os.path.expanduser("~")
    joblib = None
    HAS_JOBLIB = False

# try to import label encoder if present (used by the multiclass model)
_label_encoder = None
_rf_model = None
_xgb_model = None

# default feature order file paths (if you saved them)
_FEATURE_ORDER_FILE = os.path.join(os.path.dirname(__file__), "feature_order.json")
_SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")
_RF_PATH = os.path.join(os.path.dirname(__file__), "rf_multiclass.pkl")
_XGB_PATH = os.path.join(os.path.dirname(__file__), "xgb_multiclass.pkl")
_LABEL_ENCODER_PATH = os.path.join(os.path.dirname(__file__), "label_encoder.pkl")

def _try_load_models():
    global _label_encoder, _rf_model, _xgb_model
    if _rf_model is not None or not HAS_JOBLIB:
        return
    candidates = []
    # prefer model_loader if available
    try:
        if get_model_path:
            candidates.append(get_model_path("rf_multiclass.pkl"))
            candidates.append(get_model_path("xgb_multiclass.pkl"))
            candidates.append(get_model_path("label_encoder.pkl"))
    except Exception:
        pass
    # fallback local packaged paths
    candidates.extend([_RF_PATH, _XGB_PATH, _LABEL_ENCODER_PATH])
    # load available objects
    try:
        if os.path.exists(candidates[0]):
            _rf_model_local = joblib.load(candidates[0])
            logger.info("Loaded RF model from %s", candidates[0])
            _set_rf(_rf_model_local)
    except Exception:
        logger.debug("No RF model at %s", candidates[0], exc_info=True)
    try:
        if os.path.exists(candidates[1]):
            _xgb_local = joblib.load(candidates[1])
            logger.info("Loaded XGB model from %s", candidates[1])
            _set_xgb(_xgb_local)
    except Exception:
        logger.debug("No XGB model at %s", candidates[1], exc_info=True)
    try:
        if os.path.exists(candidates[2]):
            _label_encoder = joblib.load(candidates[2])
            logger.info("Loaded label encoder from %s", candidates[2])
    except Exception:
        logger.debug("No label encoder at %s", candidates[2], exc_info=True)

def _set_rf(m):
    global _rf_model
    _rf_model = m

def _set_xgb(m):
    global _xgb_model
    _xgb_model = m

# lightweight text-based detector used as fallback
def _text_rules_detector(text: str) -> Optional[str]:
    if not text:
        return None
    t = text.lower()
    # SQL injection heuristics
    sql_indicators = ["select ", "union ", " or ", " and ", "drop ", "insert ", "update ", "delete ", "--", "/*", "*/", "sleep(", "benchmark("]
    xss_indicators = ["<script", "javascript:", "onerror", "onload", "<img", "<svg", "alert("]
    bruteforce_indicators = ["login", "password", "passwd", "attempt", "brute", "auth failed", "failed login"]
    if any(k in t for k in sql_indicators):
        return "Web Attack - Sql Injection"
    if any(k in t for k in xss_indicators):
        return "Web Attack - XSS"
    if any(k in t for k in bruteforce_indicators):
        return "Brute Force"
    return None

def predict_text_label(text: str) -> Optional[str]:
    """
    Try ML/text model to return a readable attack label for arbitrary textual payloads.
    If no ML model exists, use simple rules.
    """
    try:
        _try_load_models()
        # if a more advanced text model exists, integrate here.
        # For now fallback to text rules:
        return _text_rules_detector(text)
    except Exception:
        logger.exception("predict_text_label failed")
        return _text_rules_detector(text)

def predict_multiclass(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Predict multiclass attack label from numeric features dict.
    Returns decision dict:
    {
      "attack_type": str|None,
      "confidence": float,
      "probs": dict|None,
      "features": features (echo)
      "reason": "ml_<something>" or "rules"
      "route": "honeypot" or "normal"
    }
    NOTE: this function is intentionally tolerant and will fall back to simple rules.
    """
    out = {
        "attack_type": None,
        "confidence": 0.0,
        "probs": None,
        "features": features,
        "reason": "unknown",
        "route": "normal"
    }

    try:
        _try_load_models()
        # if we have an RF or XGB model, use it
        if _rf_model is not None:
            # Convert features dict to vector using feature_order if available
            feature_order = None
            try:
                if os.path.exists(_FEATURE_ORDER_FILE):
                    with open(_FEATURE_ORDER_FILE, "r") as f:
                        feature_order = json.load(f)
                # else try model_loader provided feature_order
            except Exception:
                feature_order = None

            x_vec = []
            if feature_order:
                for k in feature_order:
                    v = features.get(k)
                    try:
                        x_vec.append(float(v) if v is not None else 0.0)
                    except Exception:
                        x_vec.append(0.0)
            else:
                # fallback: use the dict values in sorted key order (best-effort)
                keys = sorted(features.keys())
                for k in keys:
                    try:
                        x_vec.append(float(features.get(k) or 0.0))
                    except Exception:
                        x_vec.append(0.0)

            import numpy as np
            X = np.array(x_vec).reshape(1, -1)
            # try RF first
            try:
                probs = _rf_model.predict_proba(X)[0]
                classes = list(_rf_model.classes_)
                # choose highest
                idx = int(probs.argmax())
                label = classes[idx]
                conf = float(probs[idx])
                # try decode via label encoder if it's an encoded int
                try:
                    if _label_encoder is not None:
                        decoded = _label_encoder.inverse_transform([label])[0]
                        label = decoded
                except Exception:
                    pass
                out.update({
                    "attack_type": str(label),
                    "confidence": float(conf),
                    "probs": {str(c): float(p) for c, p in zip(classes, probs)},
                    "reason": "ml_rf",
                    "route": "honeypot" if str(label).upper() != "BENIGN" else "normal"
                })
                return out
            except Exception:
                logger.debug("RF predict_proba failed, trying XGB", exc_info=True)

        # try XGBoost scikit interface if available
        if _xgb_model is not None:
            try:
                import numpy as np
                X = np.array( [float(features.get(k) or 0.0) for k in sorted(features.keys())] ).reshape(1,-1)
                # xgb sklearn API
                probs = _xgb_model.predict_proba(X)[0]
                classes = list(_xgb_model.classes_)
                idx = int(probs.argmax())
                label = classes[idx]
                conf = float(probs[idx])
                out.update({
                    "attack_type": str(label),
                    "confidence": float(conf),
                    "probs": {str(c): float(p) for c, p in zip(classes, probs)},
                    "reason": "ml_xgb",
                    "route": "honeypot" if str(label).upper() != "BENIGN" else "normal"
                })
                return out
            except Exception:
                logger.debug("XGB predict_proba failed", exc_info=True)

    except Exception:
        logger.exception("predict_multiclass ML branch failed")

    # fallback to simple rules applied to combined textual payload or feature heuristics
    try:
        # if the caller included a textual payload in features under some known keys, check it
        text_candidates = []
        for key in ("payload", "body", "query", "uri", "url", "user_input"):
            if key in features and isinstance(features[key], str):
                text_candidates.append(features[key])
        joined_text = " ".join(text_candidates).strip()
        maybe = predict_text_label(joined_text)
        if maybe:
            out.update({
                "attack_type": maybe,
                "confidence": 0.9,
                "probs": None,
                "reason": "rules_text",
                "route": "honeypot"
            })
            return out
    except Exception:
        logger.exception("predict_multiclass fallback failed")

    # final safe default: BENIGN
    out.update({"attack_type": "BENIGN", "confidence": 0.99, "reason": "default_benign", "route": "normal"})
    return out
