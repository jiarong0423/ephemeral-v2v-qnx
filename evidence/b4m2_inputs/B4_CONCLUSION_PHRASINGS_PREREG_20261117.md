# B4 conclusion wording, pre-registered (2026-11-17; written before the first real B4M2 run and not changed afterwards; any change goes into a separate errata section)

## 1. The question
The gap "this project's rule (map, no hand-shake) 18.8% vs today's version 51%": does it come mainly from the map or from the give-way rule? The three J22B comparison groups changed the map, probing and the yield policy at the same time, so they cannot be separated.

## 2. Ablation design (2x2, probing fixed on, all other parameters as the J22B main grid)
| group | map (borrow cells) | give-way rule |
|---|---|---|
| A00 | none (knows only the segment mouths) | today's version (wait in place, request a take-over after the timeout) |
| A10 | yes | today's version (the map is only used for planning, no active yielding) |
| A01 | none | this project's rule (without a borrow cell it can only reverse to a segment mouth) |
| A11 | yes | this project's rule (= the J22B "this project's rule" group) |
Listed separately as a reference row: J22B today's version (no probing) 51%, only for comparison, not used in the effect calculation.
Measure: the take-over rate (blind-junction M2, narrow alley M1, steep slope M3, for three human-driver profiles), each cell with a 95% interval; one sweep of the human-driver parameters gives the min-max range.
- map effect = [(A00−A10)+(A01−A11)] / 2
- rule effect = [(A00−A01)+(A10−A11)] / 2
- interaction = (A00−A10)−(A01−A11)

## 3. Decision rules (on the M2 ordinary-driver main grid; M1 and M3 only as a consistency check)
1. map effect >= 2 x rule effect, and the map effect's interval excludes 0 -> use wording A.
2. rule effect >= 2 x map effect, and the rule effect's interval excludes 0 -> use wording B.
3. otherwise (less than a factor of two apart, or interaction >= half of the larger main effect) -> use wording C.
4. if a main effect's interval includes 0 -> that layer says "this simulation shows no effect" and makes no claim.
5. if the three scenes point in different directions -> add "the scenes differ" after the wording and list each scene's numbers.

## 4. The three wordings (public text in Chinese; the English version is finalised by the owner)
- **Wording A (mainly the map)**: "At the simulated blind junction the share of runs that need a human take-over fell from X% to Y%; the gap comes mainly from the shared borrow map: with the same give-way rule, having the map gives Z percentage points fewer than not having it; changing only the rule without the map gives only W points fewer. The map tells the car where to yield, and it is the core of this method."
- **Wording B (mainly the rule)**: "At the simulated blind junction the share of runs that need a human take-over fell from X% to Y%; the gap comes mainly from the give-way rule (who yields, where to, whether the gap is wide enough): changing only the rule gives W points fewer, adding the map gives Z points fewer again. The map gives the rule a place to act; the map alone has a limited effect."
- **Wording C (the two complement each other)**: "At the simulated blind junction the share of runs that need a human take-over fell from X% to Y%; the map and the rule each improve only part of it alone (Z / W percentage points), and most of the improvement appears only with both: the rule decides who yields, the map decides where to."
Closing sentence shared by all three wordings (mandatory): "All of the above is simulation; the human-driver model is taken from the literature and not calibrated on narrow alleys; the numbers are preliminary."

## 5. Facts not affected by the conclusion, kept in every wording
- The QNX-layer claims (0 entries without a permit, detect -> stopped time, the planner cannot kill the gate, kernel refusal counts, the priority-inheritance ratio) do not depend on the B4 conclusion and are written with their original numbers.
- The hand-shake is written only as an add-on: time saved between participants; it does not solve brands that do not take part or that defect.
- "800/800" only as a motivating illustration; "1.72 million runs (172 x 10,000 in the original), 0 violations" only in text.

## 6. Shipping rule if B4 is late (charter section 5)
Not finished before 11/25: ship with the verified J22B numbers + one sentence "ablation pending", marked preliminary, without delaying other deliverables.
