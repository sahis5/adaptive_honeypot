# backend/ml_model/inspect_data.py
import pandas as pd, numpy as np, os
CSV = os.path.join(os.path.dirname(__file__), '..', '..', 'dataset', 'cicids2017.csv')
print("Loading CSV (only first 100k rows for inspection)...")
df = pd.read_csv(CSV, nrows=100000)   # use subset to inspect quickly
df.columns = [c.strip() for c in df.columns]
# choose candidate features you intended to use (adjust if you used different list)
FEATURES = [
 "Flow Duration","Total Fwd Packets","Total Backward Packets",
 "Total Length of Fwd Packets","Total Length of Bwd Packets",
 "Fwd Packet Length Mean","Bwd Packet Length Mean",
 "Flow Bytes/s","Flow Packets/s","Fwd IAT Mean","Bwd IAT Mean","Packet Length Mean"
]
print("Inspecting columns (finite / inf / nan / max / min):")
for f in FEATURES:
    if f not in df.columns:
        print(f, "-> NOT FOUND")
        continue
    col = pd.to_numeric(df[f], errors='coerce')  # coerce strings -> NaN
    n_nan = col.isna().sum()
    n_inf = np.isinf(col).sum()
    n_pos_large = (col.abs() > 1e12).sum()
    maxv = col.replace([np.inf,-np.inf], np.nan).max()
    minv = col.replace([np.inf,-np.inf], np.nan).min()
    print(f"{f}: NaN={n_nan}, Inf={n_inf}, >1e12={n_pos_large}, min={minv}, max={maxv}")
