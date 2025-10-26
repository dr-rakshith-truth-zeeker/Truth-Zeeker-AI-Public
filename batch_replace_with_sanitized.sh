#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

LOGDIR="replace_log_$(date +%Y%m%dT%H%M%S)"
mkdir -p "$LOGDIR"

if [ ! -f ip_files.txt ]; then
  echo "ip_files.txt not found. Run the grep command to build it first."
  exit 1
fi

> "$LOGDIR/replaced.txt"
> "$LOGDIR/missing.txt"

while IFS= read -r origpath || [ -n "$origpath" ]; do
  [ -z "$origpath" ] && continue

  base="$(basename "$origpath")"
  name="${base%.*}"
  ext="${base##*.}"

  # candidate patterns in sanitized_outputs (common variants we used)
  patterns=(
    "sanitized_outputs/${name}*_pseudo*.${ext}"
    "sanitized_outputs/${name}*pseudo*.${ext}"
    "sanitized_outputs/*${name}*pseudo*.${ext}"
    "sanitized_outputs/${name}*.${ext}"
    "sanitized_outputs/*${name}*.${ext}"
  )

  found=""
  for pat in "${patterns[@]}"; do
    # list matched files if any; pick newest if multiples
    matches=( $pat )
    if [ "${#matches[@]}" -gt 0 ]; then
      # pick newest (ls -1t) for this pattern
      newest="$(ls -1t "${matches[@]}" 2>/dev/null | head -n1 || true)"
      if [ -n "$newest" ]; then
        found="$newest"
        break
      fi
    fi
  done

  if [ -n "$found" ]; then
    # ensure destination dir exists and copy (overwrite)
    dest="$origpath"
    mkdir -p "$(dirname "$dest")"
    cp -v -- "$found" "$dest"
    echo "$found -> $dest" >> "$LOGDIR/replaced.txt"
  else
    # no sanitized candidate found
    echo "NO_SANITIZED -> $origpath" | tee -a "$LOGDIR/missing.txt"
  fi

done < ip_files.txt

echo "Done. See $LOGDIR/replaced.txt and $LOGDIR/missing.txt"
