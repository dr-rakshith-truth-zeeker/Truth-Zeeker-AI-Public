#!/usr/bin/env python3
"""
pseudonymize_csv_ips.py

Usage:
  python3 scripts/pseudonymize_csv_ips.py input.csv output.csv

What it does:
- Finds columns whose names look like they may contain IPs or hostnames
  (matches: ip, src_ip, dst_ip, src, dst, host, hostname, sip, dip, etc.)
- Replaces unique values in those columns with host_1, host_2, ...
- Writes a JSON mapping file (saved outside repo by default) so real -> pseudo mapping
  is kept locally (does not get committed).
"""

import sys
import os
import json
import re
import pandas as pd
from collections import OrderedDict

IP_COL_PATTERN = re.compile(r"(?:^|_)(?:src|dst|sip|dip|ip|host|hostname|node)(?:$|_)", re.I)
# if you want to be more permissive, add patterns here

def find_ip_like_cols(df):
    candidates = []
    for col in df.columns:
        if IP_COL_PATTERN.search(col):
            candidates.append(col)
    return candidates

def create_mapping(values):
    mapping = OrderedDict()
    counter = 1
    for v in values:
        if pd.isna(v):
            continue
        s = str(v).strip()
        if s == "":
            continue
        if s not in mapping:
            mapping[s] = f"host_{counter}"
            counter += 1
    return mapping

def pseudonymize_series(s, mapping):
    return s.map(lambda x: mapping.get(str(x).strip()) if (pd.notna(x) and str(x).strip() in mapping) else x)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 scripts/pseudonymize_csv_ips.py input.csv output.csv")
        sys.exit(2)

    inp = sys.argv[1]
    outp = sys.argv[2]

    if not os.path.exists(inp):
        print(f"Input file not found: {inp}")
        sys.exit(3)

    print(f"Loading {inp} ...")
    df = pd.read_csv(inp, dtype=str)   # read as strings to avoid numeric coercion

    ipcols = find_ip_like_cols(df)
    if not ipcols:
        print("No columns matching ip/host patterns found. Nothing to pseudonymize.")
        df.to_csv(outp, index=False)
        print(f"Wrote copy to {outp}")
        sys.exit(0)

    print("Columns that look like IP/host fields:", ipcols)

    # build mapping across all ip-like columns (so same IP -> same host_N)
    all_values = []
    for c in ipcols:
        all_values.extend([v for v in df[c].dropna().astype(str).str.strip().unique() if v != ""])
    mapping = create_mapping(all_values)
    print(f"Found {len(mapping)} unique host values to pseudonymize.")

    # Where to save mapping? default: outside repo in home dir
    mapping_dir = os.path.expanduser("~/TruthZeeker_mappings_keep_local")
    os.makedirs(mapping_dir, exist_ok=True)
    base_name = os.path.basename(outp)
    map_file = os.path.join(mapping_dir, base_name + ".ipmap.json")

    with open(map_file, "w") as fh:
        json.dump(mapping, fh, indent=2)
    print(f"Mapping saved (local only) to: {map_file}")

    # apply mapping to columns
    for c in ipcols:
        df[c] = df[c].map(lambda x: mapping.get(str(x).strip()) if (pd.notna(x) and str(x).strip() in mapping) else x)

    df.to_csv(outp, index=False)
    print(f"Wrote pseudonymized CSV to {outp}")

if __name__ == "__main__":
    main()
