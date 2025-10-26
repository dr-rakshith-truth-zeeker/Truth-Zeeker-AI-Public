from huggingface_hub import hf_hub_download
import joblib, pprint, os

repo_id = "dr-rakshith-truth-zeeker/truth-zeeker-ai-demo"
filename = "model_20251020.joblib"   # <-- uploaded HF model filename

print("Downloading HF model...")
local_path = hf_hub_download(repo_id=repo_id, filename=filename)
print("Downloaded to:", local_path)

print("\nInspecting model.joblib contents...")
m = joblib.load(local_path)
print("type:", type(m))
if isinstance(m, dict):
    print("keys:", list(m.keys()))
    if "features" in m:
        print("features:", m["features"])
    if "pipeline" in m:
        print("has pipeline:", type(m["pipeline"]))
else:
    print("Loaded object repr:", repr(m))
