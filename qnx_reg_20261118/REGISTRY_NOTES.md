# Registry fill record (2026-11-18, owner's word "4 do 5 do 6 do")
New file: qnx_reg_20261118/b4m4_registry.tsv (hash prefix 708d3cbe7ae62e10; registry internal hash 5f9356bb). Frozen tree qnx_api_b4m5b not touched; old registry hash fbbf3c2d. Difference: registry_diff.txt (4 lines).
| key | old | new | label |
|---|---|---|---|
| b4m4:m2_drivable_w (M2 alley width) | 436 MEASURED_UNCONFIRMED | 305 | PHOTO_ESTIMATE (set by the owner) |
| b4m4:m2_bay_dep (M2 open-lot depth) | 145 | 210 | PHOTO_ESTIMATE (set by the owner) |
| seg:10.w / cell:2.lw (M1 alley width 380) | 380 MEASURED | 380 unchanged, only the endpoint text changed = outer edges of the two red lines (owner confirmed) | MEASURED |
Method and limits: the loader allows FILLED only with MEASURED / MEASURED_UNCONFIRMED (v2v_b4m4_geo.inc.c:115), while the owner wanted the label "photo estimate", so the two M2 rows stay PENDING and only the fallback value and the label changed (no code change; S188 still holds for the frozen file; the new file is not S188's object). M1's 380 was already FIXED MEASURED, so its label stays MEASURED (the owner confirmed the red-line outer-edge endpoints, consistent with the label rule).
Strata result (strata_compare.txt; geometry, no simulation; the run points V2V_B4M4_REG at the new file): M2 main geometries main / hw200 / hw220 / r600 / slope56 went from A to B (all clearances 50/70/100); the lane330 arm went from B to A; M1 and M3 unchanged (the M3 bay is still ASSUMED). M2 main at clearance 100: stop_box remaining width 237.9 < needed 310, left_band 161.6, only the junction (width 590) is usable, which is not a passing bay.
Not done: B4M4 pre-registration lock and the full three-arm comparison (need the owner's go-ahead + a resource assessment table); M3 bay size and M1 recess depth / length are still ASSUMED.
