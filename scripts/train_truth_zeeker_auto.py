import os, joblib, pandas as pd, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import matplotlib.pyplot as plt

# Path to CSV (pseudonymized)
CSV="demo_data/sanitized/zeek_features_for_training_pseudo.csv"
if not os.path.exists(CSV):
    CSV="demo_data/zeek_features_for_training.csv"
print("Using CSV:", CSV)

df = pd.read_csv(CSV)
print("Loaded rows:", len(df))
# select numeric columns
num = df.select_dtypes(include=[np.number]).copy()
# drop obvious ID / port columns if present (heuristic)
drop_keywords = ['id','time','ts','src','dst','ip','addr','port']
cols = [c for c in num.columns if not any(k in c.lower() for k in drop_keywords)]
# require non-zero variance
cols = [c for c in cols if num[c].std() > 0.0]
# fallback: if none left, take numeric columns with variance
if len(cols) == 0:
    cols = [c for c in num.columns if num[c].std() > 0.0]
# limit how many features to use
max_feats = 5
selected = cols[:max_feats]
if len(selected) == 0:
    raise SystemExit("No suitable numeric features found for training. Inspect CSV.")
print("Selected features for training:", selected)

X = num[selected].fillna(0).astype(float)

pipe = Pipeline([("scaler", StandardScaler()), ("clf", IsolationForest(n_estimators=200, contamination=0.05, random_state=42))])
print("Training IsolationForest on", X.shape, "data matrix...")
pipe.fit(X)
print("Training complete. Saving model.joblib")
joblib.dump({"pipeline":pipe,"features":selected},"model.joblib")
print("Saved model.joblib (KB):", os.path.getsize("model.joblib")//1024)

# produce histogram of anomaly scores
scores = -pipe.named_steps['clf'].score_samples(pipe.named_steps['scaler'].transform(X))
plt.figure(figsize=(6,3))
plt.hist(scores, bins=50)
plt.title("Anomaly-score distribution (higher = more anomalous)")
plt.tight_layout()
os.makedirs("demo_images", exist_ok=True)
outpng="demo_images/training_hist_auto.png"
plt.savefig(outpng, dpi=150)
print("Wrote training plot to", outpng)
