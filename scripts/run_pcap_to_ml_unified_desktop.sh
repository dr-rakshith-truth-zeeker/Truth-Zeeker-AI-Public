#!/usr/bin/env bash
# run_pcap_to_ml_unified_desktop.sh
# Single-script pipeline: runs Zeek (in Docker), waits for logs, runs embedded ML (zeek_anomaly_ml.py)
# Writes all run output under ~/Desktop/zeek_pipeline_runs/<pcapname>/run_<timestamp>/
#
# Usage:
#   ./run_pcap_to_ml_unified_desktop.sh /path/to/input.pcap [--top 20] [--contamination 0.02]

set -euo pipefail
IFS=$'\n\t'

# ---------- Config / args ----------
PCAP_PATH="${1:-}"
shift || true

if [[ -z "${PCAP_PATH}" ]]; then
  echo "Usage: $0 /path/to/input.pcap [zeek_anomaly options will be prompted later]"
  exit 2
fi

# optional ML args passed through
ML_EXTRA_ARGS="$@"

# Desktop base dir (where run dirs will be created)
DESKTOP_DIR="$HOME/Desktop"
RUNS_BASE="$DESKTOP_DIR/zeek_pipeline_runs"

# timestamp + rundir
TS="$(date -u +%Y%m%dT%H%M%SZ)"
PCAP_BN="$(basename "$PCAP_PATH" | sed 's/[^A-Za-z0-9._-]/_/g')"
RUN_DIR="$RUNS_BASE/${PCAP_BN%.*}/run_${TS}"
OUT_ML_DIR="$RUN_DIR/out_ml"

# Python candidate from zeekenv (preferred) or system python3
ZEOKENV_PY="$HOME/zeekenv/bin/python3"
PYTHON_BIN=""

# Zeek Docker image
ZEEK_IMG="zeek/zeek:4.2.0"

# ---------- Make run dir on Desktop and ensure ownership ----------
mkdir -p "$RUN_DIR"
# Try to chown/chmod so container (uid mapped) can write into it
if command -v sudo >/dev/null 2>&1; then
  sudo chown -R "$(id -u):$(id -g)" "$RUN_DIR" 2>/dev/null || true
fi
chmod -R u+rwx "$RUN_DIR" || true

echo "[INFO] Pipeline start"
echo "[INFO] PCAP: $PCAP_PATH"
echo "[INFO] Run dir: $RUN_DIR"
echo "[INFO] ML outdir: $OUT_ML_DIR"
echo

# helper: print step
step() { echo; echo "Step: $*"; }

# ---------- choose python -->
if [[ -x "$ZEOKENV_PY" ]]; then
  PYTHON_BIN="$ZEOKENV_PY"
  echo "[INFO] Using zeekenv python: $PYTHON_BIN"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
  echo "[INFO] Using system python3: $PYTHON_BIN"
else
  echo "[ERROR] No python3 found. Install python3 and required libs (pandas, sklearn, joblib, matplotlib)."
  exit 3
fi

# quick check python libs
step "Checking python imports (pandas, sklearn, joblib, matplotlib)"
python - <<PYCHECK
import sys
missing=[]
for m in ("pandas","sklearn","joblib","matplotlib","numpy"):
    try:
        __import__(m)
    except Exception as e:
        missing.append(m)
if missing:
    print("[ERROR] Missing python modules:", missing)
    sys.exit(4)
print("[INFO] Python libs OK")
PYCHECK

# ---------- write embedded ML script into run dir ----------
step "Writing embedded ML script into run folder"
mkdir -p "$OUT_ML_DIR"
ML_PY="$RUN_DIR/zeek_anomaly_ml.py"

cat > "$ML_PY" <<'PYCODE'
### BEGIN zeek_anomaly_ml.py (embedded)
#!/usr/bin/env python3
# (This is the user's zeek_anomaly_ml.py embedded. Kept intact with small path-agnostic behavior.)
# --- start user script ---
<INSERT_ZEEK_ANOMALY_PY_HERE>
# --- end user script ---
PYCODE

# Replace placeholder with the actual ML script content (we will create it properly below)
# Now overwrite the placeholder with the content the user provided - do that safely:
# We use a heredoc that contains the provided python script (the script you gave me).
cat > "$ML_PY" <<'PYML'
#!/usr/bin/env python3
# Embedded zeek_anomaly_ml.py
# (Full script content provided by user is placed below.)
# --- BEGIN USER SCRIPT ---
"""zeek_anomaly_ml.py - embedded copy"""
import argparse
import os
import sys
from pathlib import Path
import math
import pandas as pd
import numpy as np
# matplotlib may not be available in headless; script catches plot errors
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from collections import defaultdict
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib

def read_zeek_log(path):
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
        try:
            return pd.read_csv(path, sep='\t', encoding='utf-8', errors='ignore')
        except Exception:
            raise ValueError(f"No #fields header found and cannot parse: {path}")
    try:
        df = pd.DataFrame(rows, columns=fields)
    except Exception:
        df = pd.DataFrame(rows)
        df.columns = [f'c{i}' for i in range(len(df.columns))]
    df.replace({'-': pd.NA}, inplace=True)
    return df

def build_conn_per_src_features(conn_df):
    df = conn_df.copy()
    src_col = None
    for c in ('id.orig_h','src','id.orig_ip','id.orig_h '):
        if c in df.columns:
            src_col = c
            break
    if not src_col:
        raise ValueError("conn.log missing source column (id.orig_h or src)")
    df = df.rename(columns={src_col: 'src_ip'})
    for c in ('orig_bytes', 'resp_bytes', 'duration', 'orig_pkts', 'resp_pkts'):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
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
    df = dns_df.copy()
    src_col = None
    for c in ('id.orig_h','src','id'):
        if c in df.columns:
            src_col = c
            break
    if not src_col:
        raise ValueError("DNS log missing recognizable source column")
    df = df.rename(columns={src_col: 'src_ip'})
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
    df = http_df.copy()
    src_col = None
    for c in ('id.orig_h','src'):
        if c in df.columns:
            src_col = c
            break
    if not src_col:
        raise ValueError("HTTP log missing recognizable source column")
    df = df.rename(columns={src_col: 'src_ip'})
    status_col = 'status_code' if 'status_code' in df.columns else ('resp_status' if 'resp_status' in df.columns else None)
    if status_col:
        df['sc'] = df[status_col].astype(str).fillna('')
    else:
        df['sc'] = ''
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
    base = conn_df.copy()
    if 'src_ip' not in base.columns:
        raise ValueError("conn features must include 'src_ip'")
    base = base.set_index('src_ip', drop=False)
    for odf in extras_list:
        if 'src_ip' not in odf.columns:
            continue
        o = odf.set_index('src_ip', drop=False)
        base = base.join(o.drop(columns=['src_ip'], errors='ignore'), how='left', rsuffix='_r')
    base = base.fillna(0)
    return base.reset_index(drop=True)

def train_and_score(df_features, contamination=0.02, top_n=10, outdir='out_ml', save_model=True):
    os.makedirs(outdir, exist_ok=True)
    numeric_cols = df_features.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_cols:
        raise ValueError("No numeric features to train on.")
    X = df_features[numeric_cols].values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    clf = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    clf.fit(Xs)
    df_features['anomaly_score'] = -clf.decision_function(Xs)
    top = df_features.sort_values('anomaly_score', ascending=False).head(top_n)
    host_features_csv = os.path.join(outdir, 'host_features_with_scores.csv')
    top_csv = os.path.join(outdir, 'top_anomalies.csv')
    top_png = os.path.join(outdir, 'top_anomalies.png')
    df_features.to_csv(host_features_csv, index=False)
    top.to_csv(top_csv, index=False)
    try:
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
        print(f"[DEBUG] save_model flag: {save_model}")
        print(f"[DEBUG] About to save model to: {os.path.join(outdir, 'isoforest_and_scaler.joblib')}")
        print(f"[+] Saved model+scaler -> {modelpath}")
        return modelpath
    return None

def score_with_model(df_features, modelpath, outdir, top_n=10):
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
    try:
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

def extractor_for_path(p):
    bn = os.path.basename(str(p)).lower()
    if 'dns' in bn:
        return extract_dns_features
    if 'http' in bn:
        return extract_http_features
    return None

def main():
    parser = argparse.ArgumentParser(description="Zeek conn.log -> per-src features -> IsolationForest anomalies")
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

    print("[*] Reading conn.log ...")
    conn_df = read_zeek_log(str(inp))
    print(f"[+] conn.log loaded rows={len(conn_df)} cols={len(conn_df.columns)}")

    conn_features = build_conn_per_src_features(conn_df)

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

    modelpath = train_and_score(merged, contamination=args.contamination, top_n=args.top,
                                outdir=outdir, save_model=args.save_model)
    print("[+] Done.")

if __name__ == '__main__':
    main()
# --- END USER SCRIPT ---
PYML

chmod +x "$ML_PY"

echo "[INFO] Wrote embedded ML script: $ML_PY"
echo

# ---------- Run Zeek in Docker ----------
step "Running Zeek in Docker (try uid-mapped run first, fallback to privileged if AppArmor blocks)"

# ensure docker exists
if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker not found. Install Docker and retry."
  exit 4
fi

# Prepare docker mounts
PCAP_ABS="$(readlink -f "$PCAP_PATH")"
# mount pcap into container read-only at /pcap/input.pcap
# mount RUN_DIR into container at /out (read-write)
DOCKER_CMD_BASE=(docker run --rm -it --network none)
# map to host uid/gid so Zeek inside container writes files as host user (preferred)
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# Try uid-mapped run
DOCKER_CMD=("${DOCKER_CMD_BASE[@]}" -u "${HOST_UID}:${HOST_GID}" -v "${PCAP_ABS}":/pcap/input.pcap:ro -v "${RUN_DIR}":/out:rw "${ZEEK_IMG}" /bin/sh -c "cd /out && zeek -r /pcap/input.pcap -C || true; echo zeek-exited-with:$? > /out/zeek_exit_code.txt; ls -lah /out || true; tail -n 200 /out/zeek*.log 2>/dev/null || true")

echo "[DEBUG] running: ${DOCKER_CMD[*]}"
if "${DOCKER_CMD[@]}" >/tmp/run_zeek_stdout 2>&1; then
  echo "[INFO] Zeek run finished (uid-mapped). stdout logged to /tmp/run_zeek_stdout"
else
  echo "[WARN] uid-mapped Zeek run failed or produced no conn.log. Will attempt privileged fallback."
  # privileged fallback (AppArmor issues)
  DOCKER_CMD_PRIV=("${DOCKER_CMD_BASE[@]}" --privileged -v "${PCAP_ABS}":/pcap/input.pcap:ro -v "${RUN_DIR}":/out:rw "${ZEEK_IMG}" /bin/sh -c "cd /out && zeek -r /pcap/input.pcap -C || true; echo zeek-exited-with:$? > /out/zeek_exit_code.txt; ls -lah /out || true; tail -n 200 /out/zeek*.log 2>/dev/null || true")
  echo "[DEBUG] running privileged: ${DOCKER_CMD_PRIV[*]}"
  if "${DOCKER_CMD_PRIV[@]}" >/tmp/run_zeek_stdout_priv 2>&1; then
    echo "[INFO] Zeek privileged run finished. stdout logged to /tmp/run_zeek_stdout_priv"
  else
    echo "[ERROR] Zeek privileged run also failed. See /tmp/run_zeek_stdout_priv for details."
    echo "[FATAL] Zeek did not produce conn.log. Aborting pipeline."
    tail -n 200 /tmp/run_zeek_stdout_priv 2>/dev/null || true
    exit 6
  fi
fi

# show a bit of zeek stdout for debugging
echo "------ tail of zeek stdout ------"
tail -n 200 /tmp/run_zeek_stdout 2>/dev/null || tail -n 200 /tmp/run_zeek_stdout_priv 2>/dev/null || true

# ---------- verify conn.log presence ----------
step "Checking for conn.log in run dir"
CONN_CAND="$RUN_DIR/conn.log"
# Zeek may name logs as conn.log or use different prefix; search /out for conn.log-like files
CONN_F="$(find "$RUN_DIR" -maxdepth 2 -type f -name 'conn.log' -o -name 'conn.*.log' | head -n1 || true)"
if [[ -z "$CONN_F" ]]; then
  echo "[ERROR] No conn.log produced in $RUN_DIR. Listing directory:"
  ls -lah "$RUN_DIR" || true
  exit 7
fi
echo "[OK] conn.log produced: $CONN_F"

# ---------- Call the embedded ML script on the conn.log ----------
step "Running embedded ML script on logs (this will write CSV and PNG into run out_ml)"
# Pass through any ML_EXTRA_ARGS the user provided
"$PYTHON_BIN" "$ML_PY" --input "$CONN_F" --outdir "$OUT_ML_DIR" $ML_EXTRA_ARGS || {
  echo "[ERROR] ML script failed. See above"
  exit 8
}

# Ensure model saving always happens
if [[ "$ML_EXTRA_ARGS" != *"--save-model"* ]]; then
  ML_EXTRA_ARGS="$ML_EXTRA_ARGS --save-model"
  echo "[INFO] Added --save-model automatically for model persistence"
fi

# ---------- summary + preview ----------
step "ML outdir contents and preview"
ls -lah "$OUT_ML_DIR" || true
echo "---- head of first CSV (if present) ----"
FIRSTCSV="$(ls "$OUT_ML_DIR"/*.csv 2>/dev/null | head -n1 || true)"
if [[ -n "$FIRSTCSV" ]]; then
  head -n 20 "$FIRSTCSV" || true
else
  echo "No CSV found in $OUT_ML_DIR"
fi

echo
echo "[DONE] Run completed. Run folder: $RUN_DIR"
exit 0
