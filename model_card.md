# Truth-Zeeker AI — Model Card (demo)

## Overview
Small demonstration model for the Truth-Zeeker AI pipeline.  
This repo contains a tiny synthetic dataset and a demo script that trains/loads a minimal model and shows predictions.

## Intended use
Educational / research demo only. Not for production. Use only with sanitized or synthetic data.

## Model details
- Algorithm (demo): IsolationForest (scikit-learn) for anomaly scoring
- Input features: duration, orig_bytes, resp_bytes
- Output: anomaly score / binary flag

## Limitations
- Demo model is trained on synthetic data and is not validated on real traffic.
- Do not use with real PHI/PII or production network environments.

## License
MIT
