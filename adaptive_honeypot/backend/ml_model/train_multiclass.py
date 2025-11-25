# train_multiclass.py
# Location: adaptive_honeypot/backend/ml_model/train_multiclass.py

import os, json, joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

ROOT = os.path.dirname(__file__)
CSV = os.path.join(ROOT, '..', '..', 'dataset', 'cicids2017.csv')

# features chosen earlier (trimmed names)
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

OUT_RF = os.path.join(ROOT, 'rf_multiclass.pkl')
OUT_XGB = os.path.join(ROOT, 'xgb_multiclass.pkl')
OUT_SCALER = os.path.join(ROOT, 'scaler.pkl')
OUT_ORDER = os.path.join(ROOT, 'feature_order.json')
OUT_LE = os.path.join(ROOT, 'label_encoder.pkl')

print("Loading CSV from:", CSV)
# flexible usecols: match stripped names
desired = set([c.strip() for c in FEATURES] + ['Label'])
def usecols_fn(colname):
    return colname.strip() in desired

df = pd.read_csv(CSV, usecols=usecols_fn, low_memory=False)
df.columns = [c.strip() for c in df.columns]

missing = [f for f in FEATURES if f not in df.columns]
if missing:
    print("Missing features after strip:", missing)
    print("Available columns sample:", df.columns.tolist()[:80])
    raise SystemExit(1)
if 'Label' not in df.columns:
    print("Label column missing")
    raise SystemExit(1)

print("Rows loaded:", len(df))

# --- cleaning (same safe steps) ---
for c in FEATURES:
    df[c] = pd.to_numeric(df[c], errors='coerce')
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# fix zero duration flows
if 'Flow Duration' in df.columns:
    zero_mask = (df['Flow Duration'] == 0) | (df['Flow Duration'].isna())
    if zero_mask.any():
        if 'Total Length of Fwd Packets' in df.columns:
            df.loc[zero_mask & df['Total Length of Fwd Packets'].notna(), 'Flow Bytes/s'] = \
                df.loc[zero_mask & df['Total Length of Fwd Packets'].notna(), 'Total Length of Fwd Packets']
        df.loc[zero_mask & df['Flow Bytes/s'].isna(), 'Flow Bytes/s'] = 0.0
        df.loc[zero_mask & df['Flow Packets/s'].isna(), 'Flow Packets/s'] = 0.0

df.replace([np.inf, -np.inf], np.nan, inplace=True)

# clip extremes
for c in FEATURES:
    col = df[c]
    if col.dropna().empty:
        continue
    q_low = col.quantile(0.001)
    q_high = col.quantile(0.999)
    if pd.notna(q_low) and pd.notna(q_high) and q_high > q_low:
        df[c] = col.clip(lower=q_low, upper=q_high)

print("NaN counts before drop:", df[FEATURES + ['Label']].isna().sum().to_dict())
before = len(df)
df = df.dropna(subset=FEATURES + ['Label'])
after = len(df)
print(f"Dropped {before-after} rows. Remaining: {after}")

# sample for speed: adjust SAMPLE=None to use all
SAMPLE = 200000
if SAMPLE and len(df) > SAMPLE:
    df = df.sample(n=SAMPLE, random_state=42)
    print("Sampled to", len(df))

# prepare X and y (multi-class)
X = df[FEATURES].astype(float)
y_raw = df['Label'].astype(str).str.strip()
print("Label sample counts (raw):")
print(y_raw.value_counts().head(20))

# --- handle rare labels by grouping into 'OTHER' ---
MIN_COUNT = 10
label_counts = y_raw.value_counts()
rare_labels = label_counts[label_counts < MIN_COUNT].index.tolist()
if rare_labels:
    print(f"Grouping rare labels (count < {MIN_COUNT}) into 'OTHER': {rare_labels}")
    y_raw = y_raw.apply(lambda x: 'OTHER' if x in rare_labels else x)
else:
    print("No rare labels to group.")

print("Label counts after grouping:")
print(y_raw.value_counts())
# --- end grouping ---

# encode labels
le = LabelEncoder()
y_enc = le.fit_transform(y_raw)
joblib.dump(le, OUT_LE)
print("Saved LabelEncoder to", OUT_LE)
print("Classes:", list(le.classes_))

# split
X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

# scale
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)
joblib.dump(scaler, OUT_SCALER)
with open(OUT_ORDER, 'w') as f:
    json.dump(FEATURES, f)
print("Saved scaler and feature order.")

# RandomForest multiclass
print("Training RandomForest (multiclass)...")
rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)
rf.fit(X_train_s, y_train)
joblib.dump(rf, OUT_RF)
print("Saved RF multiclass to", OUT_RF)

# XGBoost multiclass (optional)
try:
    print("Training XGBoost (multiclass)...")
    xgb_clf = xgb.XGBClassifier(objective='multi:softprob', num_class=len(le.classes_),
                                n_estimators=200, use_label_encoder=False, eval_metric='mlogloss', random_state=42)
    xgb_clf.fit(X_train_s, y_train)
    joblib.dump(xgb_clf, OUT_XGB)
    print("Saved XGBoost to", OUT_XGB)
except Exception as e:
    print("XGBoost skipped/failed:", e)

# evaluate (show classification report on decoded labels)
print("\n=== RandomForest Report ===")
y_pred = rf.predict(X_test_s)
y_test_labels = le.inverse_transform(y_test)
y_pred_labels = le.inverse_transform(y_pred)
print(classification_report(y_test_labels, y_pred_labels))
print("Confusion matrix (decoded labels):")
print(confusion_matrix(y_test_labels, y_pred_labels))

if os.path.exists(OUT_XGB):
    xgbm = joblib.load(OUT_XGB)
    print("\n=== XGBoost Report ===")
    y_pred2 = xgbm.predict(X_test_s)
    y_pred2_labels = le.inverse_transform(y_pred2)
    print(classification_report(y_test_labels, y_pred2_labels))

print("Training (multiclass) complete.")
