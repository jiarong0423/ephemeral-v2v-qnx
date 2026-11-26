# Scene measurement from the reference clip (2026-11-04)

Measurement record. The reference is a third-party social-media clip (2026-10-25, widely reposted). The clip and its frames are not part of this repository; only the numbers and the scripts are.

## Source
- Clip: screen recording of the X post, 30.7 s, 650 x 1122 px; the video area is the 650 x 360 px crop at y = 590.
- Location: not identified.
- How it ended (replies and reposts, several independent accounts; the clip itself ends before): the two-seat car (car C) backed up and broke the deadlock; the pod (car A) moved aside and reversed at one point; a human-driven car behind the pod also reversed and honked.

## Method (frame t = 2 s, `frame_t2s.png`)
1. Segmentation: SAM ViT-B (`sam_vit_b_01ec64.pth`, the public Segment Anything checkpoint), point prompts on the pod, the SUV and the SUV's front tyre. Script: `sam_measure.py`; raw output: `f2_sam.json`; overlay: `frame_t2s_sam_overlay.png` (green pod, blue SUV, red tyre, yellow kerb lines).
2. Kerb: Canny edges + probabilistic Hough lines, steep lines in the left third of the frame. Best kerb line (20,153)-(121,308) in crop pixels.
3. Scale: SUV front tyre mask height 64 px; tyre outer diameter taken as 0.74 m -> about 86 px/m at the depth of the SUV's nose.
4. Gaps on the same image row as the ground contact:
   - kerb x ~ 44 px -> SUV nose x ~ 258 px on row y ~ 190 (points picked by hand on the overlay): **about 2.5 m**; +/- 0.3 m is our allowance for picking those pixels;
   - kerb x ~ 20 px -> pod's kerb-side wheel x ~ 75 px: **about 0.65-0.85 m** (scale 66-84 px/m from the pod's own width, which mixes front face and side).
5. Consequence: the pod is 1.9 m wide; with its kerb side at 0.65-0.85 m its other side is at 2.55-2.75 m, just past the SUV's nose at about 2.5 m. A step of a few tens of centimetres toward the kerb clears it; the model, with a 20 cm margin and the nose corners' full geometry, uses all the room minus the margin (55 cm).

## Limits (first pass; the second pass below re-measured car A's kerb gap and the positions along the street)
Single frame, hand-held phone, no lens calibration, perspective approximated by a single scale per row. Distances along the street (pod to the car behind it, the 50 cm) are **not** measured; they remain estimates. The street width (then about 7.7 m, now 7.9 m) is an estimate that fits the far-side car; the gap behind car A is now about 1.9 m, still an estimate.

## Sensitivity (`sensitivity.sh`, host build, 2026-11-04, after the planner fixes; first-pass values, superseded, not repeated for the second pass)
Car A's gap to the kerb and the lowest corner of car B's nose, both measured from the kerb:

| Pod to kerb | Nose corner to kerb 2.15 m | 2.45 m (used) | 2.75 m |
| :-- | :-- | :-- | :-- |
| 65 cm | pod steps 45 cm, passes; then SUV; then two-seat car | same, 45 cm | no deadlock |
| 75 cm (used) | pod steps 55 cm | pod steps 55 cm (hash 0xBF82DC91) | no deadlock |
| 85 cm | pod steps 65 cm | pod steps 65 cm | pod steps 65 cm |

In no case does the SUV have to back up. The step is always all the free room minus the 20 cm margin.

## Values written into the simulation (superseded, first pass)
Car A (pod) d = -60 cm (kerb at -230, so 75 cm from the kerb), human-driven car 50 cm behind it (sends no frame), car B (SUV) centre d = 184 cm (lowest nose corner 245 cm from the kerb), car C d = 445 cm, dumpster further back at s = -1250 cm.

## Second pass (2026-11-04 evening): far side, the person, the kerb gap by gutter grid
Tool: `visual_measure.py` with the hand-picked points in `visual_points_t25s.json` (frame at about 25 s, filmed from the near sidewalk behind car B; frame sha256 in the JSON, frame kept internal). Log: `visual_measure.log`. Re-run:

    python3 -I evidence/scene_measurement/visual_measure.py evidence/scene_measurement/visual_points_t25s.json --check --overlay <out.png>

Expected: `RESULT: PASS`, exit 0 (1 = a value outside its tolerance, 2 = bad input). The tool reads the clip frames in `internal_frames/`, which are third-party and kept out of the repository; from a clone it stops with `ERROR: frame not found` and exit 2. The PASS recorded here was run in our private working copy, where the frames are.

1. Kerb gap of car A. First read on this frame with the gutter grid (a US city's standard 18 in = 45.72 cm gutter as one cell): 62 cm and 87 cm. The owner ruled 75 cm wrong. Re-measured on the 6 s frame (`visual_points_t06s.json`, filmed from ahead of car A) with car A's own 1.9 m width as the scale on its front-axle row: **about 116 cm**. The line picked as the kerb face on the 25 s frame is most likely the gutter seam, one cell too far out, so that grid result is kept only as a record and no longer checked. Car A is straight (owner's ruling from the 5, 6 and 8 s frames); SIM[] uses 110 cm.
2. Ground-plane depth (along the street). Car B's two wheels (wheelbase 299 cm, heading -160 deg) fix the scale; distance along the camera axis is proportional to 1 / (y - horizon). The horizon is outside the frame, so it is swept over y = 240-300; the results move by less than 5 cm across the sweep.

| Point | Frame (s along the street) | SIM[] | Check |
| :-- | :-- | :-- | :-- |
| Parked white SUV, rear bumper | -84 to -82 cm | -75 cm | PASS (+/- 60 cm) |
| Car C, front wheel | 214 to 218 cm | 206 cm | PASS (+/- 60 cm) |
| The one person, feet (in the gap behind the SUV) | -14 to -10 cm | 0 cm | PASS |
| Car A to the kerb (6 s frame, own width as scale) | 116 cm | 110 cm, straight | PASS (+/- 15 cm) |

Cross-check against the other frames:
- t = 2 s (SAM, first pass): car A 0.65-0.85 m from the kerb, car B's nose about 2.45 m from the kerb. Still used; with the first-pass 75 cm, car A's far side (75 + 190 = 265 cm) overlaps car B's nose corner by about 20 cm, so neither can go straight on.
- Owner's frames at 5, 6 and 8 s (filmed from ahead of car A): car A square to the kerb; car B's nose just ahead of car A's face, on car A's side of the street.
- Frames at 13-23 s: car C beside car B's rear on the far side; car C's front level with car B's rear part.
- Owner's observations: only one person counts, standing behind the white SUV; people elsewhere are not obstacles.

Values now in `SIM[]`: street 7.9 m between the kerbs (d = -230 .. 560; widened from 7.7 m so the parked cars and car C keep 20-28 cm to the far kerb, as they do in the clip); car A s = -418.5, d = -25, straight (110 cm from the kerb); car B s = 10, d = 184, heading -165 (the clip reads about -160; -165 is within the +/- 5 deg reading and keeps B's rear corner about 25 cm from car C, where -160 left 4 cm); car C s = 351, d = 449 (moved 16 cm along the street, inside the +/- 60 cm tolerance, and 4 cm toward the far kerb, which leaves 23.5 cm, inside the 20-28 cm seen in the clip); human-driven car s = -1030 (about 1.9 m behind car A, an estimate, 1.2-2.7 m); dumpster s = -1400; parked white SUV s = -315, d = 445; parked car s = -930, d = 450; one person s = 0, d = 470. Gap from the SUV's rear to car C's front: about 2.0 m, with the person in it. The ground-plane depth step above still uses B's clip heading of -160 deg; at -165 deg its scale changes by under 3 %.
Plan with these values (host build, `$TMPDIR` harness including the source): 5 steps, hash 0x128AA057: 1. C backs off (450 cm, 930 cm free), 2. C waits clear, 3. A steps toward the kerb (90 cm), 4. A passes, 5. B passes (B has 100 cm free behind it). Without car A's frame car C computes 0xFFA5BE2D (no deadlock seen), so the votes differ and every car holds.
