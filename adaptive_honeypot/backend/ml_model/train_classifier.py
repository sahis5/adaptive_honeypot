# backend/ml_model/train_classifier.py
# Small synthetic training to create a quick classifier if CICIDS not available.
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

OUT = os.path.join(os.path.dirname(__file__), 'classifier.pkl')

def create_synthetic_dataset(n=2000):
    # features: pkt_len, req_rate, num_special_chars, has_sql_keywords(0/1)
    rng = np.random.RandomState(42)
    pkt_len = rng.normal(500, 200, n).clip(20, 2000)
    req_rate = rng.exponential(1.0, n)  # requests/sec
    num_special = rng.poisson(2, n)
    has_sql = (rng.rand(n) < 0.1).astype(int)
    # label: BENIGN or ATTACK
    # simple rule: if has_sql or req_rate>3 or num_special>6 => ATTACK
    label = np.where((has_sql==1) | (req_rate > 3) | (num_special > 6), 'ATTACK', 'BENIGN')
    df = pd.DataFrame({
        'pkt_len': pkt_len,
        'req_rate': req_rate,
        'num_special': num_special,
        'has_sql': has_sql,
        'label': label
    })
    return df

def train_and_save():
    df = create_synthetic_dataset()
    X = df[['pkt_len','req_rate','num_special','has_sql']]
    y = df['label']
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    joblib.dump(clf, OUT)
    print("Saved classifier to", OUT)

if __name__ == "__main__":
    train_and_save()
