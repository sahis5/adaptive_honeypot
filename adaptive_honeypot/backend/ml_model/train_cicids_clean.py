# train_cicids_clean.py
# Put this file at: adaptive_honeypot/backend/ml_model/train_cicids_clean.py

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

ROOT = os.path.dirname(__file__)
CSV = os.path.join(ROOT, '..', '..', 'dataset', 'cicids2017.csv')

# --------- feature list (chosen for your CSV) ----------
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
 "Packet Length Mean"
]

OUT_RF = os.path.join(ROOT, 'rf_classifier.pkl')
OUT_XGB = os.path.join(ROOT, 'xgb_classifier.pkl')
OUT_SCALER = os.path.join(ROOT, 'scaler.pkl')
OUT_ORDER = os.path.join(ROOT, 'feature_order.json')

print("Reading CSV (selecting needed columns by stripped name) from:", CSV)

# define set of desired column names after stripping spaces
desired = set([c.strip() for c in FEATURES] + ['Label'])

# usecols as callable: keep any column whose stripped name is in desired
def usecols_fn(colname):
    return colname.strip() in desired

# read CSV using callable usecols so it matches even with extra spaces
df = pd.read_csv(CSV, usecols=usecols_fn, low_memory=False)
# normalize column names by stripping whitespace
df.columns = [c.strip() for c in df.columns]

# verify features exist now
missing = [f for f in FEATURES if f not in df.columns]
if missing:
    print("Error: these required features are missing from the CSV after strip:", missing)
    print("Available columns sample:", df.columns.tolist()[:80])
    raise SystemExit(1)

label_col = 'Label'
if label_col not in df.columns:
    print("Error: 'Label' column not found in CSV after strip.")
    raise SystemExit(1)

print("Initial rows loaded:", len(df))

# ------------------ CLEANING ------------------

# 1) coerce chosen features to numeric (non-numeric -> NaN)
for c in FEATURES:
    df[c] = pd.to_numeric(df[c], errors='coerce')

# 2) replace infinite values with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# 3) Fix potential division-by-zero derived fields:
# If Flow Duration == 0, try to approximate Flow Bytes/s and Flow Packets/s using totals
if 'Flow Duration' in df.columns:
    zero_mask = (df['Flow Duration'] == 0) | (df['Flow Duration'].isna())
    if zero_mask.any():
        if 'Total Length of Fwd Packets' in df.columns:
            df.loc[zero_mask & df['Total Length of Fwd Packets'].notna(), 'Flow Bytes/s'] = \
                df.loc[zero_mask & df['Total Length of Fwd Packets'].notna(), 'Total Length of Fwd Packets']
        df.loc[zero_mask & df['Flow Bytes/s'].isna(), 'Flow Bytes/s'] = 0.0
        df.loc[zero_mask & df['Flow Packets/s'].isna(), 'Flow Packets/s'] = 0.0

# 4) double-check and replace any remaining inf
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# 5) Clip extreme outliers per feature (0.1% - 99.9% quantiles)
print("Clipping extreme values using 0.1% and 99.9% quantiles for each feature.")
for c in FEATURES:
    col = df[c]
    if col.dropna().empty:
        continue
    q_low = col.quantile(0.001)
    q_high = col.quantile(0.999)
    if pd.notna(q_low) and pd.notna(q_high) and q_high > q_low:
        df[c] = col.clip(lower=q_low, upper=q_high)

# 6) Show NaN counts before dropping
print("NaN counts (per chosen feature) BEFORE drop:")
print(df[FEATURES + [label_col]].isna().sum())

# 7) Drop any rows that still have NaN in required features or label
before = len(df)
df = df.dropna(subset=FEATURES + [label_col])
after = len(df)
print(f"Dropped {before - after} rows with missing required features. Remaining rows: {after}")

# 8) Optional sampling to limit memory usage for quick iteration
SAMPLE = 200000   # change lower if memory issues; set None to use all rows
if SAMPLE and len(df) > SAMPLE:
    df = df.sample(n=SAMPLE, random_state=42)
    print("Sampled down to", len(df), "rows for training")

# ----------------- PREPARE DATA -----------------
X = df[FEATURES].astype(float)
y = df[label_col].apply(lambda s: 'BENIGN' if str(s).strip().upper() == 'BENIGN' else 'ATTACK')

print("Final dataset shape:", X.shape)
print("Label distribution:")
print(y.value_counts())

# train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# scale
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# save scaler and feature order
joblib.dump(scaler, OUT_SCALER)
with open(OUT_ORDER, 'w') as f:
    json.dump(FEATURES, f)
print("Saved scaler and feature order to:", OUT_SCALER, OUT_ORDER)

# ----------------- TRAIN MODELS -----------------
print("Training RandomForest...")
rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)
rf.fit(X_train_s, y_train)
joblib.dump(rf, OUT_RF)
print("Saved RandomForest to:", OUT_RF)

# XGBoost (try/except in case xgboost not installed or fails)
try:
    print("Training XGBoost (this may take longer)...")
    xgb_clf = xgb.XGBClassifier(objective='binary:logistic', n_estimators=200,
                                use_label_encoder=False, eval_metric='logloss', random_state=42)
    xgb_clf.fit(X_train_s, y_train)
    joblib.dump(xgb_clf, OUT_XGB)
    print("Saved XGBoost to:", OUT_XGB)
except Exception as e:
    print("XGBoost training skipped or failed:", e)

# ----------------- EVALUATION -----------------
print("\n=== RandomForest Evaluation ===")
y_pred = rf.predict(X_test_s)
print(classification_report(y_test, y_pred))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

if os.path.exists(OUT_XGB):
    xgbm = joblib.load(OUT_XGB)
    print("\n=== XGBoost Evaluation ===")
    y_pred2 = xgbm.predict(X_test_s)
    print(classification_report(y_test, y_pred2))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred2))

print("Training complete.")
