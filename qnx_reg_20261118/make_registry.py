#!/usr/bin/env python3
"""Build the 2026-11-18 owner-confirmed registry from the FROZEN b4m5b registry (never edits the frozen tree). Exit 1 on any failed assert."""
import sys, hashlib
SRC = "<local-scratch>/qnx_api_b4m5b/qnx_target/data/b4m4_registry.tsv"
DST = "<local-scratch>/qnx_reg_20261118/b4m4_registry.tsv"
SRCNOTE = "video + paint-line measurement (qnx_reg_20261118/REGISTRY_NOTES.md; owner instruction 2026-11-18: label it a photo estimate)"
lines = open(SRC, encoding="utf-8").read().split("\n")
out, hit = [], {}
for ln in lines:
    c = ln.split("\t")
    k = c[0]
    if len(c) == 12 and k == "b4m4:m2_drivable_w":
        assert c[2] == "PENDING" and c[9] == "436"
        c[9], c[10], c[11] = "305", "PHOTO_ESTIMATE", SRCNOTE + "; replaces 436 (the alley getting wider further in was a bias; owner confirmed the alley body has one width)"
        hit[k] = 1
    elif len(c) == 12 and k == "b4m4:m2_bay_dep":
        assert c[2] == "PENDING" and c[9] == "145"
        c[9], c[10], c[11] = "210", "PHOTO_ESTIMATE", SRCNOTE + "; replaces 145 (depth of the open lot)"
        hit[k] = 1
    elif len(c) == 12 and k in ("seg:10.w", "cell:2.lw"):
        assert c[2] == "FIXED" and c[3] == "380" and c[5] == "MEASURED"
        c[7] = "between the outer edges of the two red lines (owner confirmed 2026-11-18: both tape ends on the outer edges of the red lines)"
        hit[k] = 1
    out.append("\t".join(c))
assert len(hit) == 4, hit
open(DST, "w", encoding="utf-8").write("\n".join(out))
print("wrote", DST, hashlib.sha256(open(DST, "rb").read()).hexdigest()[:16])
