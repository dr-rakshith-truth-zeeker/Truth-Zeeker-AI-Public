#!/usr/bin/env python3
"""
regenerate_top_anomalies_png.py

Usage:
  python3 scripts/regenerate_top_anomalies_png.py sanitized_csv output_png

Creates a simple bar chart of top N anomaly_score by host (descending).
"""

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt

def plot_top_anomalies(csv_path, out_png, top_n=10):
    df = pd.read_csv(csv_path)
    # require 'anomaly_score' and a host column - try to auto-detect
    if 'anomaly_score' not in df.columns:
        raise ValueError("CSV does not contain 'anomaly_score' column")

    # try to detect a host column (column containing host_ or src_ip)
    host_cols = [c for c in df.columns if 'host' in c.lower() or 'src' in c.lower() or 'ip' in c.lower()]
    # prefer exact 'src_ip' or a 'host' named column
    host_col = None
    for h in ['src_ip','host','src_host','hostname','src_hostname','sip','src']:
        if h in [c.lower() for c in df.columns]:
            host_col = [c for c in df.columns if c.lower()==h][0]
            break
    if host_col is None:
        # fallback to first host-like column
        host_col = host_cols[0] if host_cols else None

    if host_col is None:
        # if we can't find host column, create synthetic index labels
        df['__host_label'] = [f"row_{i}" for i in range(len(df))]
        host_col = '__host_label'

    # aggregate by host (if duplicates exist) taking mean anomaly_score
    agg = df.groupby(host_col).agg({
        'anomaly_score': 'mean'
    }).sort_values('anomaly_score', ascending=False)

    top = agg.head(top_n)
    plt.figure(figsize=(10, 6))
    ax = top['anomaly_score'].plot.bar(rot=45)
    ax.set_title("Top anomaly scores")
    ax.set_ylabel("Anomaly score")
    ax.set_xlabel("Host")
    plt.tight_layout()
    os.makedirs(os.path.dirname(out_png) or '.', exist_ok=True)
    plt.savefig(out_png)
    plt.close()
    print(f"Saved plot to: {out_png}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 scripts/regenerate_top_anomalies_png.py sanitized_csv output_png")
        sys.exit(2)
    csv_path = sys.argv[1]
    out_png = sys.argv[2]
    plot_top_anomalies(csv_path, out_png)
