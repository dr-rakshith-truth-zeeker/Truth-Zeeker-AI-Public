#!/usr/bin/env bash
set -euo pipefail

echo "Running repository sanity checks..."

# 1) Ensure no tracked capture files
if git ls-files -oi --exclude-standard | egrep -i '\.pcap$|\.cap$|\.pcapng$' >/dev/null; then
  echo "ERROR: repository contains tracked capture files (pcap/cap/pcapng). Aborting."
  git ls-files -oi --exclude-standard | egrep -i '\.pcap$|\.cap$|\.pcapng$'
  exit 1
fi
echo "OK: no tracked capture files"

# 2) Ensure no tracked model binaries
if git ls-files -oi --exclude-standard | egrep -i '\.joblib$|\.pkl$' >/dev/null; then
  echo "ERROR: repository contains tracked model binaries (.joblib/.pkl). Aborting."
  git ls-files -oi --exclude-standard | egrep -i '\.joblib$|\.pkl$'
  exit 1
fi
echo "OK: no tracked model binaries"

# 3) Search tracked text files for dotted IPv4 addresses (ignores binary files)
#    Writes matches to /tmp/zz_ip_matches and then filters out expected docnet 203.0.113.x.
git ls-files -z | xargs -0 grep -nE --binary-files=without-match "([0-9]{1,3}\.){3}[0-9]{1,3}" > /tmp/zz_ip_matches 2>/dev/null || true

if [ -s /tmp/zz_ip_matches ]; then
  # Remove docnet 203.0.113.x matches (expected for sanitized snapshot)
  filtered=$(grep -v -E '203\.0\.113\.[0-9]{1,3}' /tmp/zz_ip_matches || true)
  if [ -n "$filtered" ]; then
    echo "ERROR: possible dotted IPv4 addresses found in tracked text files:"
    printf '%s\n' "$filtered" | head -n 40
    echo "If these are docnet-mapped addresses (203.0.113.x), verify and ignore intentionally."
    exit 1
  else
    echo "OK: only docnet-mapped addresses (203.0.113.x) found — ignoring."
  fi
else
  echo "OK: no dotted IPv4 addresses in tracked text files"
fi

echo "Sanity checks passed."

