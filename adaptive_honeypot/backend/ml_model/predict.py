# backend/ml_model/predict.py
import os, joblib, json, numpy as np

ROOT = os.path.dirname(__file__)
RF_PATH = os.path.join(ROOT, 'rf_classifier.pkl')
SCALER_PATH = os.path.join(ROOT, 'scaler.pkl')
ORDER_PATH = os.path.join(ROOT, 'feature_order.json')

if not os.path.exists(RF_PATH) or not os.path.exists(SCALER_PATH) or not os.path.exists(ORDER_PATH):
    raise FileNotFoundError("Model/scaler/feature_order not found. Run train_cicids_clean.py first.")

_rf = joblib.load(RF_PATH)
_scaler = joblib.load(SCALER_PATH)
_order = json.load(open(ORDER_PATH))

def predict_from_features(features: dict):
    """
    features: dict mapping the exact feature names (from feature_order.json) -> numeric values
    returns: label string (e.g., 'BENIGN' or 'ATTACK')
    """
    # build ordered array expected by the scaler/model
    arr = [float(features.get(k, 0.0)) for k in _order]
    arr_s = _scaler.transform([arr])
    pred = _rf.predict(arr_s)[0]
    return pred

def predict_proba(features: dict):
    arr = [float(features.get(k, 0.0)) for k in _order]
    arr_s = _scaler.transform([arr])
    probs = _rf.predict_proba(arr_s)[0]
    # return dict label->prob
    labels = _rf.classes_
    return dict(zip(labels, map(float, probs)))
