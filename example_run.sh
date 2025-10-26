#!/usr/bin/env bash
set -e
python3 - <<'PY'
import os, joblib, pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

csv_path = "demo_data/sample_features.csv"
model_path = "model.joblib"

# load demo data (ignore comment lines)
df = pd.read_csv(csv_path, comment='#')
print("Loaded demo data shape:", df.shape)
print(df.head())

if os.path.exists(model_path):
    print("Found model.joblib — loading existing model.")
    model = joblib.load(model_path)
else:
    print("No model.joblib found — training a tiny demo IsolationForest model.")
    X = df[['duration','orig_bytes','resp_bytes']].values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(n_estimators=50, contamination=0.2, random_state=42)
    model.fit(Xs)
    # save a pipeline-like object (scaler + model)
    joblib.dump((scaler, model), model_path)
    print("Saved demo model to", model_path)

# load pipeline
scaler, model = joblib.load(model_path)
X = df[['duration','orig_bytes','resp_bytes']].values
Xs = scaler.transform(X)
scores = model.decision_function(Xs)
preds = model.predict(Xs)  # -1: anomaly, 1: normal

out = df.copy()
out['anomaly_score'] = scores
out['anomaly_flag'] = preds
print("\\nDemo results (first 10 rows):")
print(out.head(10).to_string(index=False))
# optionally save small output CSV
out.to_csv("demo_data/sample_output_with_scores.csv", index=False)
print("\\nSaved demo_data/sample_output_with_scores.csv")
PY
