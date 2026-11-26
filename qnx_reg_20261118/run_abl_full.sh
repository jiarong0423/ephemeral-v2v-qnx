#!/usr/bin/env bash
# run_abl_full.sh - B4M4 three-arm ablation (A00/A01/A11), full: 8910 settings x 200 trials, 40 shards, 4 workers. SIMULATION only.
# Resumable: a finished shard dir is renamed from shard_NN.tmp to shard_NN and skipped on rerun. Per-process peak 211 MB measured (4 workers = 0.85 GB).
# Stop: touch $OUT/STOP, or free memory < 20 % (checked between shards). Exit non-zero when any shard failed.
set -u; set -o pipefail
N="<local-scratch>/qnx_reg_20261118"
OUT="${ABL_OUT:-$N/abl_full}"; BIN="$N/work/qnx_target"; REG="$N/b4m4_registry.tsv"; STR="$N/strata_new/strata.csv"
SH=40; TR=200; WORKERS=4
mkdir -p "$OUT"; LOG="$OUT/run.log"
say() { echo "$(date +%H:%M:%S) $*" | tee -a "$LOG"; }
shard() {
  i=$1; d="$OUT/shard_$(printf %02d "$i")"
  [ -d "$d" ] && { echo "skip $i"; return 0; }
  [ -e "$OUT/STOP" ] && { echo "STOP seen, shard $i not started"; return 3; }
  free=$(memory_pressure 2>/dev/null | awk '/free percentage/ {gsub("%","",$5); print $5}')
  [ -n "${free:-}" ] && [ "$free" -lt 20 ] && { echo "ERROR free memory ${free}% < 20%, shard $i not started"; return 4; }
  rm -rf "$d.tmp"; mkdir -p "$d.tmp"
  (cd "$BIN" && env V2V_SPEC2_B4M4ABL=1 V2V_B4M4_REG="$REG" V2V_B4M4_STRATA="$STR" V2V_B4M4_SHARD="$i/$SH" build/sim --spec2-sim "$TR" --spec2-out "$d.tmp") > "$d.tmp/run.log" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && grep -q "RESULT: PASS" "$d.tmp/run.log"; then mv "$d.tmp" "$d"; echo "ok shard $i"; else echo "ERROR shard $i rc=$rc (see $d.tmp/run.log)"; return 1; fi
}
export -f shard; export OUT BIN REG STR SH TR
say "start: registry $(shasum -a 256 "$REG" | cut -c1-16) strata $(shasum -a 256 "$STR" | cut -c1-16) shards $SH trials $TR workers $WORKERS"
seq 0 $((SH-1)) | xargs -P "$WORKERS" -I{} bash -c 'shard {}' 2>&1 | tee -a "$LOG"
fails=$(grep -c "^ERROR\|STOP seen" "$LOG" || true)
n_ok=$(ls -d "$OUT"/shard_[0-9][0-9] 2>/dev/null | wc -l | tr -d ' ')
say "finished shards ok=$n_ok of $SH, errors/stops=$fails"
if [ "$n_ok" -eq "$SH" ]; then
  python3 -B - "$OUT" <<'PY' >> "$LOG" 2>&1 || { echo "ERROR merge"; exit 1; }
import sys,glob
out=sys.argv[1]
for name in ("spec2_b4m4abl.csv","spec2_b4m4abl_runs.csv"):
    files=sorted(glob.glob(f"{out}/shard_[0-9][0-9]/{name}")); assert len(files)==40, (name,len(files))
    hdr=None; n=0
    with open(f"{out}/{name}","w",encoding="utf-8") as w:
        for f in files:
            L=open(f,encoding="utf-8").read().split("\n")
            if hdr is None: hdr=L[0]; w.write(hdr+"\n")
            assert L[0]==hdr
            for ln in L[1:]:
                if ln: w.write(ln+"\n"); n+=1
    print("merged",name,"rows",n)
PY
  say "MERGED"; exit 0
fi
exit 1
