# backend/ml_model/train_cicids_exact.py
import os, joblib, json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

ROOT = os.path.dirname(__file__)
CSV = os.path.join(ROOT, '..', '..', 'dataset', 'cicids2017.csv')

# --------------- chosen features (exact) ----------------
FEATURES = [
 "Flow Duration",
 "Total Fwd Packets",
 "Total Backward Packets",
 "Total Length of Fwd Packets",
 "Total Length of Bwd Packets",
 "Fwd Packet Length Mean",
 "Bwd Packet Length Mean",
 "Flow Bytes/s",
 "Flow Packets/s",
 "Fwd IAT Mean",
 "Bwd IAT Mean",
 "Packet Length Mean"   # note: we'll strip whitespace from df columns
]

OUT_RF = os.path.join(ROOT, 'rf_classifier.pkl')
OUT_XGB = os.path.join(ROOT, 'xgb_classifier.pkl')
OUT_SCALER = os.path.join(ROOT, 'scaler.pkl')
OUT_ORDER = os.path.join(ROOT, 'feature_order.json')

print("Loading CSV:", CSV)
df = pd.read_csv(CSV)

# normalize column names: strip leading/trailing whitespace
df.columns = [c.strip() for c in df.columns.tolist()]

# verify features present
available = df.columns.tolist()
missing = [f for f in FEATURES if f not in available]
if missing:
    print("Error: these chosen features are missing from CSV:", missing)
    print("Available sample columns:", available[:40])
    raise SystemExit(1)

# label column name
label_col = None
for cand in ['Label','label','CLASS','Category','Attack']:
    if cand in df.columns:
        label_col = cand
        break
if not label_col:
    print("ERROR: no Label column found. Please ensure dataset has 'Label'.")
    raise SystemExit(1)

# drop rows with NaNs in chosen features + label
df2 = df.dropna(subset=FEATURES + [label_col]).copy()
print("Rows after dropna:", len(df2))

# define X, y (binary: BENIGN vs ATTACK)
X = df2[FEATURES].astype(float)
y = df2[label_col].apply(lambda s: 'BENIGN' if str(s).strip().upper() == 'BENIGN' else 'ATTACK')

# train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# scale
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# save scaler + feature order
joblib.dump(scaler, OUT_SCALER)
with open(OUT_ORDER, 'w') as f:
    json.dump(FEATURES, f)
print("Saved scaler and feature order.")

# Random Forest
rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)
rf.fit(X_train_s, y_train)
joblib.dump(rf, OUT_RF)
print("Saved RF model to", OUT_RF)

# XGBoost
try:
    xgb_clf = xgb.XGBClassifier(objective='binary:logistic', n_estimators=200, use_label_encoder=False, eval_metric='logloss', random_state=42)
    xgb_clf.fit(X_train_s, y_train)
    joblib.dump(xgb_clf, OUT_XGB)
    print("Saved XGB model to", OUT_XGB)
except Exception as e:
    print("XGBoost failed:", e)

# Evaluate RF
print("\n=== RandomForest Evaluation ===")
y_pred = rf.predict(X_test_s)
print(classification_report(y_test, y_pred))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

# Evaluate XGB if available
if os.path.exists(OUT_XGB):
    xgbm = joblib.load(OUT_XGB)
    print("\n=== XGBoost Evaluation ===")
    y_pred2 = xgbm.predict(X_test_s)
    print(classification_report(y_test, y_pred2))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred2))

print("Training complete.")
