### BEGIN zeek_anomaly_ml.py
#!/usr/bin/env python3
"""
zeek_anomaly_ml.py

Usage (train):
  python3 zeek_anomaly_ml.py --input conn.log --outdir ./out_ml \
      --top 20 --contamination 0.02 --extra-logs ./dns.log,./http.log --save-model

Usage (score only with saved model):
  python3 zeek_anomaly_ml.py --input conn.log --outdir ./out_ml --score-only \
      --model ./out_ml/isoforest_and_scaler.joblib --extra-logs ./dns.log,./http.log
"""

import argparse
import os
import sys
from pathlib import Path
import math

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

# ML
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib

# ------------------------------------------------------------
# Basic Zeek log reader (tab-separated with #fields header)
# ------------------------------------------------------------
def read_zeek_log(path):
    """Read Zeek-style tab-separated log with a #fields header line.
    Returns a pandas DataFrame (strings)."""
    path = str(path)
    if path.endswith('.gz'):
        import gzip
        opener = gzip.open
        mode = 'rt'
    else:
        opener = open
        mode = 'r'
    fields = None
    rows = []
    with opener(path, mode, encoding='utf-8', errors='ignore') as fh:
        for ln in fh:
            line = ln.rstrip('\n')
            if not line:
                continue
            if line.startswith('#fields'):
                parts = line.split('\t')
                fields = parts[1:]
                continue
            if line.startswith("#"):
                continue
            rows.append(line.split('\t'))
    if not fields:
        # minimal attempt: try to read CSV with header
        try:
            return pd.read_csv(path, sep='\t', encoding='utf-8', errors='ignore')
        except Exception:
            raise ValueError(f"No #fields header found and cannot parse: {path}")
    # Build DataFrame
    try:
        df = pd.DataFrame(rows, columns=fields)
    except Exception:
        # fallback - create wide DF and slice columns if mismatch
        df = pd.DataFrame(rows)
        df.columns = [f'c{i}' for i in range(len(df.columns))]
    # Replace Zeek '-' with NaN
    df.replace({'-': pd.NA}, inplace=True)
    return df

# ------------------------------------------------------------
# Feature extractors
# ------------------------------------------------------------
def build_conn_per_src_features(conn_df):
    """Produce a DataFrame of per-src features from a Zeek conn.log DataFrame."""
    df = conn_df.copy()
    # Accept a few possible source column names
    src_col = None
    for c in ('id.orig_h','src','id.orig_ip','id.orig_h '):
        if c in df.columns:
            src_col = c
            break
    if not src_col:
        raise ValueError("conn.log missing source column (id.orig_h or src)")
    df = df.rename(columns={src_col: 'src_ip'})
    # numeric coercions
    for c in ('orig_bytes', 'resp_bytes', 'duration', 'orig_pkts', 'resp_pkts'):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
    # basic aggregations
    agg = df.groupby('src_ip').agg(
        conn_count = ('src_ip','count'),
        total_orig_bytes = ('orig_bytes','sum') if 'orig_bytes' in df.columns else ('src_ip','count'),
        total_resp_bytes = ('resp_bytes','sum') if 'resp_bytes' in df.columns else ('src_ip','count'),
        unique_dst_ports = ('id.resp_p', lambda s: s.dropna().nunique()) if 'id.resp_p' in df.columns else ('src_ip','nunique'),
        avg_duration = ('duration', 'mean') if 'duration' in df.columns else ('src_ip','count'),
        total_orig_pkts = ('orig_pkts','sum') if 'orig_pkts' in df.columns else ('src_ip','count'),
        total_resp_pkts = ('resp_pkts','sum') if 'resp_pkts' in df.columns else ('src_ip','count')
    ).reset_index()
    return agg

def extract_dns_features(dns_df):
    """Return DataFrame indexed by src_ip with DNS features: query count, unique domains, nxdomain count"""
    df = dns_df.copy()
    # find src column
    src_col = None
    for c in ('id.orig_h','src','id'):
        if c in df.columns:
            src_col = c
            break
    if not src_col:
        raise ValueError("DNS log missing recognizable source column")
    df = df.rename(columns={src_col: 'src_ip'})
    # query and rcode
    if 'query' in df.columns:
        df['query_norm'] = df['query'].astype(str)
    else:
        df['query_norm'] = pd.NA
    def is_nxd(r):
        v = r.get('rcode', '')
        if pd.isna(v):
            return 0
        s = str(v).lower()
        return 1 if s in ('3','nxdomain') else 0
    if 'rcode' in df.columns:
        df['is_nxd'] = df.apply(is_nxd, axis=1)
    else:
        df['is_nxd'] = 0
    g = df.groupby('src_ip').agg(
        dns_query_count = ('query_norm','count'),
        dns_unique_domains = ('query_norm', lambda s: s.dropna().nunique()),
        dns_nx_count = ('is_nxd','sum')
    ).reset_index()
    return g

def extract_http_features(http_df):
    """Return DataFrame indexed by src_ip with simple HTTP features."""
    df = http_df.copy()
    src_col = None
    for c in ('id.orig_h','src'):
        if c in df.columns:
            src_col = c
            break
    if not src_col:
        raise ValueError("HTTP log missing recognizable source column")
    df = df.rename(columns={src_col: 'src_ip'})
    # status code variations
    status_col = 'status_code' if 'status_code' in df.columns else ('resp_status' if 'resp_status' in df.columns else None)
    if status_col:
        df['sc'] = df[status_col].astype(str).fillna('')
    else:
        df['sc'] = ''
    # bytes
    resp_len_col = 'resp_len' if 'resp_len' in df.columns else ('body_len' if 'body_len' in df.columns else None)
    if resp_len_col:
        df[resp_len_col] = pd.to_numeric(df[resp_len_col], errors='coerce').fillna(0)
    g = df.groupby('src_ip').agg(
        http_count = ('src_ip','count'),
        http_unique_hosts = ('host', lambda s: s.dropna().nunique()) if 'host' in df.columns else ('src_ip','nunique'),
        http_2xx = ('sc', lambda s: s.str.startswith('2').sum()),
        http_4xx = ('sc', lambda s: s.str.startswith('4').sum()),
        http_bytes = (resp_len_col, 'sum') if resp_len_col else ('src_ip','count')
    ).reset_index()
    return g

def merge_features(conn_df, extras_list):
    """Merge conn_df (per-src features) with a list of extra per-src DataFrames (each with src_ip)."""
    base = conn_df.copy()
    if 'src_ip' not in base.columns:
        raise ValueError("conn features must include 'src_ip'")
    base = base.set_index('src_ip', drop=False)
    for odf in extras_list:
        if 'src_ip' not in odf.columns:
            continue
        o = odf.set_index('src_ip', drop=False)
        # join and fillna(0)
        base = base.join(o.drop(columns=['src_ip'], errors='ignore'), how='left', rsuffix='_r')
    base = base.fillna(0)
    return base.reset_index(drop=True)

# ------------------------------------------------------------
# ML training + scoring pipeline
# ------------------------------------------------------------
def train_and_score(df_features, contamination=0.02, top_n=10, outdir='out_ml', save_model=False):
    """Train IsolationForest on numeric columns of df_features (per-src) and produce outputs."""
    os.makedirs(outdir, exist_ok=True)
    # pick numeric columns
    numeric_cols = df_features.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_cols:
        raise ValueError("No numeric features to train on.")
    X = df_features[numeric_cols].values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    clf = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    clf.fit(Xs)
    # use decision_function -> lower means more anomalous (neg larger anomaly). We invert for 'score' so higher=more anomalous
    df_features['anomaly_score'] = -clf.decision_function(Xs)
    # sort
    top = df_features.sort_values('anomaly_score', ascending=False).head(top_n)
    # write outputs
    host_features_csv = os.path.join(outdir, 'host_features_with_scores.csv')
    top_csv = os.path.join(outdir, 'top_anomalies.csv')
    top_png = os.path.join(outdir, 'top_anomalies.png')
    df_features.to_csv(host_features_csv, index=False)
    top.to_csv(top_csv, index=False)
    # quick bar plot for top anomalies (by src_ip)
    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(10,6))
        ax = plt.barh(top['src_ip'].astype(str), top['anomaly_score'])
        plt.gca().invert_yaxis()
        plt.xlabel('Anomaly score (higher = more anomalous)')
        plt.title(f'Top {top_n} anomalous source IPs')
        plt.tight_layout()
        plt.savefig(top_png, dpi=180)
        plt.close()
    except Exception as e:
        print(f"[!] Plot failed: {e}")
    print(f"[+] Wrote: {host_features_csv}, {top_csv}, {top_png}")
    if save_model:
        modelpath = os.path.join(outdir, 'isoforest_and_scaler.joblib')
        joblib.dump({'clf': clf, 'scaler': scaler, 'numeric_cols': numeric_cols}, modelpath)
        print(f"[+] Saved model+scaler -> {modelpath}")
        return modelpath
    return None

def score_with_model(df_features, modelpath, outdir, top_n=10):
    """Load saved model and use it to score df_features (must include required numeric columns)."""
    loaded = joblib.load(modelpath)
    clf = loaded['clf']
    scaler = loaded['scaler']
    needed_cols = loaded.get('numeric_cols', [])
    for c in needed_cols:
        if c not in df_features.columns:
            df_features[c] = 0
    X = df_features[needed_cols].values
    Xs = scaler.transform(X)
    df_features['anomaly_score'] = -clf.decision_function(Xs)
    top = df_features.sort_values('anomaly_score', ascending=False).head(top_n)
    os.makedirs(outdir, exist_ok=True)
    host_features_csv = os.path.join(outdir, 'host_features_with_scores_scored.csv')
    top_csv = os.path.join(outdir, 'top_anomalies_scored.csv')
    df_features.to_csv(host_features_csv, index=False)
    top.to_csv(top_csv, index=False)
    # plot
    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(10,6))
        ax = plt.barh(top['src_ip'].astype(str), top['anomaly_score'])
        plt.gca().invert_yaxis()
        plt.xlabel('Anomaly score (higher = more anomalous)')
        plt.title(f'Top {top_n} anomalous source IPs (scored)')
        plt.tight_layout()
        plt.savefig(os.path.join(outdir, 'top_anomalies_scored.png'), dpi=180)
        plt.close()
    except Exception as e:
        print(f"[!] Plot failed: {e}")
    print(f"[+] Wrote: {host_features_csv}, {top_csv}")
    return None

# ------------------------------------------------------------
# Helper: pick extractor by filename
# ------------------------------------------------------------
def extractor_for_path(p):
    bn = os.path.basename(str(p)).lower()
    if 'dns' in bn:
        return extract_dns_features
    if 'http' in bn:
        return extract_http_features
    # add more heuristics here (tls, ssl, files...) as needed
    return None

# ------------------------------------------------------------
# Main CLI
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Zeek conn.log -> per-src features -> IsolationForest anomalies\n"
                                     "Can optionally ingest extra Zeek logs (dns/http) and merge features.")
    parser.add_argument('--input','-i', required=True, help='Path to Zeek conn.log (plain or .gz)')
    parser.add_argument('--outdir','-o', default='./out_ml', help='Output directory')
    parser.add_argument('--top','-t', type=int, default=10, help='Top-N to record/plot')
    parser.add_argument('--contamination','-c', type=float, default=0.02, help='IsolationForest contamination')
    parser.add_argument('--extra-logs', help='Comma-separated extra Zeek logs (dns.log,http.log etc). Optional.')
    parser.add_argument('--save-model', action='store_true', help='Save fitted model+scaler')
    parser.add_argument('--score-only', action='store_true', help='Load existing model (--model) and score input features only')
    parser.add_argument('--model', help='Path to model joblib (required with --score-only)')
    args = parser.parse_args()

    inp = Path(args.input)
    if not inp.exists():
        print(f"[ERROR] Input not found: {inp}")
        sys.exit(2)

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    # read conn log
    print("[*] Reading conn.log ...")
    conn_df = read_zeek_log(str(inp))
    print(f"[+] conn.log loaded rows={len(conn_df)} cols={len(conn_df.columns)}")

    # base conn per-src features
    conn_features = build_conn_per_src_features(conn_df)

    # if extra logs specified, attempt to extract
    extras = []
    if args.extra_logs:
        for p in str(args.extra_logs).split(','):
            p = p.strip()
            if not p:
                continue
            if not os.path.exists(p):
                print(f"[!] extra log not found (skipping): {p}")
                continue
            try:
                df = read_zeek_log(p)
            except Exception as e:
                print(f"[!] failed reading extra log {p}: {e}")
                continue
            ext = extractor_for_path(p)
            if ext is None:
                print(f"[i] No extractor available for '{p}' (you can add one). Skipping.")
                continue
            try:
                feat = ext(df)
                extras.append(feat)
                print(f"[+] Extracted features from {p} -> {len(feat)} rows")
            except Exception as e:
                print(f"[!] extractor failed for {p}: {e}")

    merged = merge_features(conn_features, extras) if extras else conn_features.copy()
    print(f"[+] Merged features shape: {merged.shape}")

    if args.score_only:
        if not args.model:
            print("[ERROR] --score-only requires --model path")
            sys.exit(2)
        score_with_model(merged, args.model, outdir, top_n=args.top)
        print("[+] Score-only complete")
        return

    # train + score
    modelpath = train_and_score(merged, contamination=args.contamination, top_n=args.top,
                                outdir=outdir, save_model=args.save_model)
    print("[+] Done.")

if __name__ == '__main__':
    main()
### END zeek_anomaly_ml.py
