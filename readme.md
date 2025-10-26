Truth-Zeeker AI v1.0

Automated Zeek + ML Pipeline for Network Anomaly Detection

Truth-Zeeker AI is an experimental hybrid security-analytics pipeline that automates network-traffic parsing and anomaly detection using Zeek logs, Python, and unsupervised ML.
It’s designed for quick forensic insights and educational research — not for production deployment.

✳️ Features

Parses .pcap traffic via Zeek (Docker-based run with automatic privilege / AppArmor fallback)

Generates Zeek log artifacts (conn.log, dhcp.log, dns.log, etc.)

Feeds data to a Python ML pipeline (zeek_anomaly_ml.py) using pandas, matplotlib, and scikit-learn

Produces CSV summaries + anomaly-score plots

Optionally saves a trained Isolation Forest + Scaler model (isoforest_and_scaler.joblib)

Tested fully offline in a Parrot OS VM using a pre-downloaded Zeek 4.2.0 Docker image

## 📁 Project Layout (Release Branch)

```text
Truth-Zeeker-AI/
├── docs/                        # Notes, references, dependency info
├── outputs/                     # Sanitized demo CSVs & PNGs
├── samples_sanitized/           # Public-safe .pcap samples (mapped to 203.0.113.0/24)
│   ├── http_sanitized_docnet.cap
│   └── vlan_sanitized_docnet.cap
├── scripts/                     # Main automation & ML scripts
│   ├── run_pcap_to_ml_unified_desktop.sh
│   ├── zeek_anomaly_ml.py
│   ├── zeek_enrich_and_plot.py
│   └── pseudonymization utilities
├── inspect_hf_model.py          # HF model inspection / verification helper
└── readme.md                    # Main documentation (you’re reading it)
```

⚙️ Requirements
Base Environment

Parrot OS / Kali / Ubuntu 20.04+

Docker (tested with zeek/zeek:4.2.0)

Python 3.8+ (with venv)

Optional offline use: docker load -i zeek_image.tar

Python Packages
pip install pandas matplotlib seaborn scikit-learn joblib


Optional (debug):

pip install numpy tqdm


Tested in: Isolated VM (no external network) with ~/zeekenv/bin/python3.

▶️ Example Usage

1️⃣ Basic run (no model save)

./scripts/run_pcap_to_ml_unified_desktop.sh ./samples_sanitized/http_sanitized_docnet.cap


2️⃣ Train + save model

./scripts/run_pcap_to_ml_unified_desktop.sh ./samples_sanitized/vlan_sanitized_docnet.cap --save-model


Outputs appear under:

~/Desktop/zeek_pipeline_runs/<pcap_name>/run_<timestamp>/

☁️ Model & Demo Integration

Hugging Face Repo: dr-rakshith-truth-zeeker/truth-zeeker-ai-demo

model_20251020.joblib → trained Isolation Forest model

zeek_features_for_training_pseudo.csv → pseudonymized training features

Colab Demo: Truth-Zeeker AI Colab Notebook (Visualization + Inference)

Loads the HF model & demo CSV

Generates top_anomalies.png and summary metrics

🔐 Sanitization & Privacy

All capture files mapped to the documentation-reserved 203.0.113.0/24 range.

No RFC1918 (10.x, 172.16/12, 192.168/16) or real public IPs remain in tracked files.

CSV outputs and charts were pseudonymized via custom scripts in scripts/.

No raw malware traffic or PII is included in the public repo.

⚠️ Disclaimer

Truth-Zeeker AI is intended solely for educational and research use.
Do not deploy in production or analyze real patient data.
All samples are benign and publicly available from trusted sources (e.g., Wireshark Wiki).

Users are responsible for compliance with local laws and institutional policies.

📈 Future Work

Integrate with a lightweight Security Onion deployment for live capture

Extend ML models & automated retraining

Add GUI dashboard for CSV/PNG visuals

Explore integration opportunities for specialized domains (e.g., imaging system or IoT network telemetry)

## 🧠 Authors
**Rakshith J.** — Concept, testing, and development  
**ChatGPT (OpenAI)** — Pipeline logic & code design assistance

---

## 📜 License
MIT License © 2025 Rakshith J.  
Free to fork, modify, and extend for educational or research purposes.


✅ Change Summary (v1.0)

Replaced private 10.x addresses with 203.0.113.0/24 doc-net range

Removed all raw captures from release branch

Added sanitized samples and HF model integration

Updated .gitignore to exclude raw data and models
