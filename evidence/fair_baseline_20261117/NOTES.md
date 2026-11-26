# Fairer baselines: two earlier host runs (2026-11-17)

These two result files were produced by an earlier tree of our host C simulator than the `50 cm` headline
(`qnx_reg_20261118/`, B4M4 geometry registry of 2026-11-18). They are published unchanged because they answer
"what if the baseline car were given our map, or yielded by habit?". Both were run twice and the two runs were
bit-identical (rerun summary of 2026-11-17: `spec2_b4abl.csv` `94ec41c749b88c09` run1 = run2, `90720` settings,
`RESULT PASS`; `spec2_j22b.csv` `e82a409ed745ce2a` run1 = run2).

| File | sha256 | Bytes |
|---|---|---|
| `spec2_b4abl.csv` | `94ec41c749b88c096cfcaa00707a314d4c0127024f18399ff88532027718f9d6` | `17,829,262` |
| `spec2_j22b.csv` | `e82a409ed745ce2a10edc8057ffc7155d864a8b48131a194f1fc43c0f4487e2c` | `3,630,603` |

The code that defines both blocks is in `j24c/qnx_target/src/v2v_spec2_sim.inc.c` (policy enum `J2B_ALWAYS` /
`J2B_RANDOM` at line `3595`, block `P` policy pairs at lines `4534-4540`, the 2x2 ablation arms at lines `4876-4879`).
That file belongs to a later tree; the per-row hashes in the CSVs were not recomputed against it.

## 1. The waiting car with our borrow-cell map (arm `A10`, B4M2 ablation, block `AB`)

`1,080` settings x `200` trials per arm and clearance (car meets one simulated human driver).

| Clearance | `A00` wait, no map | `A10` wait + map | `A01` our rule, no map | `A11` our rule + map |
|---|---|---|---|---|
| `50 cm` | `31.096%` | `31.096%` | `0.107%` | `0.116%` |
| `70 cm` | `33.122%` | `33.122%` | `4.035%` | `4.035%` |
| `100 cm` | `35.846%` | `35.846%` | `14.263%` | `14.263%` |

Giving the waiting car the map alone does not change its take-over rate (`A10` = `A00` in every clearance).

    awk -F, 'NR>1 && $1=="AB"{k=$3" "$8; to[k]+=$17; tr[k]+=$16} END{for(x in to) printf "%s %d/%d %.3f%%\n", x, to[x], tr[x], 100*to[x]/tr[x]}' spec2_b4abl.csv | sort

## 2. Cars that yield by habit (block `P`, J22B, car meets car)

`432` settings (3 scenes x 6 x 6 policy slots x clearance `50` / `100 cm` x 2 open speeds), `200` trials each.
`pol0` / `pol1` = the yield policy of the first / second car (`proj` = our rule, `always`, `never`, `random`).
Take-over share = sum of the `takeovers` column / sum of `trials`.

| `pol0` | with `always` | with `never` | with `proj` | with `random` |
|---|---|---|---|---|
| `always` | `0.00%` | `0.00%` | `0.00%` | `0.00%` |
| `random` | `0.00%` | `0.00%` | `0.00%` | `0.00%` |
| `proj` (our rule) | `0.00%` | `0.00%` | `0.00%` | `0.00%` |
| `never` | `23.92%` | `59.42%` | `24.25%` | `24.03%` |

In this block a first car that always yields, or yields at random, had no take-overs, the same as our rule;
take-overs appear only when the first car never yields. So the headline `32.05% -> 0.061%` compares our rule with a
car that never yields on its own; on take-over rate alone this block shows no advantage of our rule over a car
that yields by habit. Other columns (wait and pass times, livelocks) were not analysed for this note.

    awk -F, 'NR==1{for(i=1;i<=NF;i++)h[$i]=i; next} $1=="P"{k=$h["pol0"]"/"$h["pol1"]; to[k]+=$h["takeovers"]; tr[k]+=$h["trials"]} END{for(x in to) printf "%s %d/%d %.2f%%\n", x, to[x], tr[x], 100*to[x]/tr[x]}' spec2_j22b.csv | sort
