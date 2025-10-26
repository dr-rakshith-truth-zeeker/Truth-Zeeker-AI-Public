Truth-Zeeker AI — Documentation Notes
=====================================

Environment:
------------
- Tested on Parrot OS Security Edition (VM)
- Python virtual environment: ~/zeekenv
- Docker image: zeek/zeek:4.2.0
- Network: isolated (--network none)
- Zeek output: conn.log, dns.log, dhcp.log, weird.log
- ML output: host_features_with_scores.csv, top_anomalies.csv, top_anomalies.png

Dependencies:
-------------
- pandas
- matplotlib
- seaborn
- scikit-learn
- joblib
- Python 3.8+ recommended
- Docker CE 24+

Execution Workflow:
-------------------
1. Zeek parses pcap using Docker container
2. Logs stored in run_<timestamp>/
3. Python ML module parses logs, computes anomaly scores, and saves results
4. Optional: --save-model flag saves .joblib in out_ml directory

Notes:
------
- Large mixed-interface pcapng files may require manual preprocessing.
- Testing done offline for safety; no internet access used during ML runs.
- For best performance, ensure the pcap files are standard `.pcap` format with consistent snapshot lengths.
