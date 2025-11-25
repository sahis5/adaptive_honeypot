# predict_multiclass.py
# Path: adaptive_honeypot/backend/ml_model/predict_multiclass.py

import os, joblib, json, numpy as np
from typing import Tuple, Dict

ROOT = os.path.dirname(__file__)
RF_PATH = os.path.join(ROOT, 'rf_multiclass.pkl')
SCALER_PATH = os.path.join(ROOT, 'scaler.pkl')
ORDER_PATH = os.path.join(ROOT, 'feature_order.json')
LE_PATH = os.path.join(ROOT, 'label_encoder.pkl')

if not (os.path.exists(RF_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(ORDER_PATH) and os.path.exists(LE_PATH)):
    raise FileNotFoundError("One or more model artifacts missing. Run train_multiclass.py first.")

_rf = joblib.load(RF_PATH)
_scaler = joblib.load(SCALER_PATH)
_order = json.load(open(ORDER_PATH))
_le = joblib.load(LE_PATH)

# convenience: decode classes
CLASS_NAMES = list(_le.classes_)

def _build_array_from_features(features: dict):
    """Build ordered numpy array for model from feature dict (fills missing with 0.0)."""
    arr = []
    for k in _order:
        # allow keys present with slightly different whitespace
        val = features.get(k)
        if val is None:
            # also try stripped keys
            for fk in features.keys():
                if fk.strip() == k:
                    val = features.get(fk)
                    break
        try:
            arr.append(float(val) if val is not None else 0.0)
        except Exception:
            arr.append(0.0)
    return np.array(arr, dtype=float).reshape(1, -1)

def predict_multiclass(features: dict) -> Tuple[str, Dict[str, float]]:
    """
    Returns: (predicted_label_str, probs_dict)
    probs_dict maps label -> probability (floats)
    """
    arr = _build_array_from_features(features)
    arr_s = _scaler.transform(arr)
    probs = _rf.predict_proba(arr_s)[0]  # array aligned with _rf.classes_
    # rf.classes_ are encoded integers; we map via label encoder
    # sklearn's RF with multiclass trained on label-encoded integers may have classes_ = array([0,1,2,...])
    # use _le.inverse_transform to map back
    # first get encoded classes ordering
    try:
        encoded_classes = _rf.classes_
        decoded = _le.inverse_transform(encoded_classes)
        probs_dict = {str(lbl): float(p) for lbl, p in zip(decoded, probs)}
    except Exception:
        # fallback: assume _le.classes_ alignment
        probs_dict = {str(lbl): float(p) for lbl, p in zip(CLASS_NAMES, probs)}
    # predicted label
    pred_idx = int(_rf.predict(arr_s)[0])
    try:
        pred_label = _le.inverse_transform([pred_idx])[0]
    except Exception:
        # fallback to most probable label from probs_dict
        pred_label = max(probs_dict.items(), key=lambda x: x[1])[0]
    return pred_label, probs_dict

def predict_proba_only(features: dict) -> Dict[str, float]:
    return predict_multiclass(features)[1]
