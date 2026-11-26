#!/usr/bin/env bash
# run_strata.sh - build the frozen b4m5b sim (B4M4 flags, no B4M5) in a temp dir and compute geometry strata for the OLD and the NEW registry. Geometry only; no simulation.
set -u; set -o pipefail
N="<local-scratch>/qnx_reg_20261118"
SRC="<local-scratch>/qnx_api_b4m5b"
W="${TMPDIR:-/tmp}/qnx_reg_strata_$$"; rm -rf "$W"; mkdir -p "$W" || exit 2
OSSL=/opt/homebrew/opt/openssl@3
D="-DV2V_SPEC2 -DV2V_J20 -DV2V_J21 -DV2V_J21B -DV2V_J22 -DV2V_J22B -DV2V_EMERG -DV2V_B4MAP -DV2V_B4M3 -DV2V_B4M4 -DV2V_PC"
rsync -a --exclude '/qnx_target/build*' --exclude '.claude' "$SRC/qnx_target" "$W/" || { echo "ERROR rsync"; exit 2; }
mkdir -p "$W/qnx_target/build"
(cd "$W/qnx_target" && cc -O2 -ffp-contract=off -Iinclude $D -I"$OSSL/include" -L"$OSSL/lib" -Wl,-rpath,"$OSSL/lib" src/v2v_ttl_resmgr.c -o build/sim -lcrypto -lm) > "$N/build.log" 2>&1 || { echo "ERROR build, see $N/build.log"; exit 1; }
for tag in old new; do
  if [ $tag = old ]; then REG="$SRC/qnx_target/data/b4m4_registry.tsv"; else REG="$N/b4m4_registry.tsv"; fi
  mkdir -p "$N/strata_$tag"
  (cd "$W/qnx_target" && env V2V_SPEC2_B4M4STRATA=1 V2V_B4M4_REG="$REG" build/sim --spec2-sim 1 --spec2-out "$N/strata_$tag") > "$N/strata_$tag.log" 2>&1
  rc=$?; echo "$tag rc=$rc: $(grep -m1 RESULT "$N/strata_$tag.log" | cut -c1-230)"
  [ $rc -eq 0 ] || { echo "ERROR strata $tag, see $N/strata_$tag.log"; exit 1; }
done
rm -rf "$W"; echo DONE
