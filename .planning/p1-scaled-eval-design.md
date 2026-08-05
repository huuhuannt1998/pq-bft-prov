# P1 scaled-evaluation + statistics + baseline DESIGN (for PI approval before compute)

Purpose: harden the correlated-fragility finding and the attribution spine to "thin evidence" and
"missing baselines" reviews. Nothing here is run until the PI approves sampling + baseline framing.
Standing discipline: dev/held-out disjoint; existence-and-direction for adaptive/multi-turn; no
prevention leaderboard; report whatever it shows.

## A. Model matrix (#9) — separate per-FAMILY lineage from per-model QUALITY
Six families x two models each (12 models), spanning sizes/quant so we can test whether "robust vs weak"
tracks lineage or just capability:

| Family (lineage) | Model A | Model B | have/pull |
|---|---|---|---|
| Llama (Meta) | llama3.1:8b | llama3.2:3b | pull B |
| Qwen (Alibaba) | qwen2.5:7b | qwen2.5:3b | have both |
| Mistral (Mistral) | mistral:7b | mistral-nemo:12b | pull B |
| Gemma (Google) | gemma3:4b | gemma2:9b | pull B |
| Phi (Microsoft) | phi3.5:3.8b | phi4:14b | pull both |
| Granite (IBM) | granite3.1-dense:8b | granite3.1-moe:3b | pull both |

Analysis: regress each susceptibility axis on {family, params, quant} — if family dominates and size does
not, "stable per-family property" holds; if size/quality dominates, we revise to "capability artifact."
All local, Q4_K_M where available, temp 0. (Lean fallback if compute is too high: 5 families x 2 = 10.)

## B. Five-axis per-model decomposition (#9), each with a 95% CI
Per model, report: (a) clean-task utility (legit-channel approve), (b) benign-unsafe approval (baseline
honest-error), (c) single-shot IPI susceptibility (injected marginal), (d) adaptive susceptibility,
(e) multi-turn susceptibility. Wilson score interval on every proportion.

## C. Scaled held-out corpus (#8) — target ~120 payloads, disjoint from the 12 dev + current 24
Five categories x ~24 each, across the 22-device set, 3 sophistication levels:
1. forged-authorization  2. channel-impersonation  3. safety-pretext  4. social-proof
5. NEW: retrieval/RAG-style non-instruction poisoning (cf. Machine Against the RAG) — poisoned retrieved
   documents that bias toward approval WITHOUT an explicit embedded instruction (tests whether the
   instruction-data-separation prompt, which keys on "instruction in data," even applies).
Construction is templated + hand-audited for realism (no degenerate near-direct commands). The current
24 become a validated subset; all disjoint from the 12 dev payloads.

## D. Statistics plan (#6) — applied to every table
- Proportions: Wilson 95% score intervals; always show k/n.
- Paired within-payload comparisons (prompt ON vs OFF; single-shot vs multi-turn; our prompt vs StruQ):
  McNemar exact test, report the discordant pairs and p.
- Unpaired (family vs family): Fisher exact.
- phi / co-failure (#7): bootstrap 95% CI over payloads (10k resamples). PRE-REGISTERED decision rule:
  * if the phi CI excludes 0 on the low side only or straddles 0 with meaningful positive mass ->
    report "insufficient evidence for same-payload correlated failure in this sample" (do NOT assert
    independence);
  * if the CI is tight around 0 -> report near-zero phi WITH the CI as evidence against same-payload
    co-failure. Either way we never assert independence from a point estimate.
- No bare point estimates anywhere; n and CI on every cell.

## E. N=7 scaling across MULTIPLE compositions (#10)
Enumerate compositions of 7 agents from the model pool: round-robin, weak-weighted, robust-weighted,
and >=5 random draws. For each, quorum-defeat outcome on the adaptive + a held-out subset. Report the
distribution/variance of defeats across compositions (not one composition). Cheap: computed from the
per-model family-level votes we already collect in B/C, plus a few real N=7 certificates for the floor.

## F. Adaptive + multi-turn breadth (#11) — still existence-and-direction
- Adaptive: expand from 1 defeating family to >=6 distinct forged-provenance strategies x targets;
  report how many defeat the quorum, per model, with the stability (K reps) distribution.
- Multi-turn: expand from 5 to ~18 scenarios; situate against Crescendo (multi-turn escalation) and
  cite it; report single-shot vs multi-turn paired (McNemar). Framing stays "breakable, not a rate."

## G. Baseline (#13) — REFRAMED as generality of the finding, NOT a prevention leaderboard
- StruQ-style structured-prompt / instruction-data-separation defense reimplemented as a drop-in on the
  SAME vote path. Measure two things only: (i) does it yield cross-family fault-independence? (expected:
  no — still one shared defense), (ii) does it break under adaptive + multi-turn? (expected: yes). Result
  either way SUPPORTS our thesis (the correlated-fragility is a property of shared prompt-level defenses,
  not of our particular prompt). We do NOT claim our prevention beats StruQ.
- IsolateGPT / ACE: positioned CONCEPTUALLY in related work — isolation / information-flow / trusted-
  planning is a different paradigm whose security does NOT rest on the diversity-independence premise we
  refute, so they are complementary, not competitors. No head-to-head prevention numbers claimed.
- If StruQ reimplementation proves impractical, principled surrogate: our own VOTE_SYSTEM already IS an
  instruction-data-separation defense; we add ONE published structured-prompt variant (spotlighting /
  delimiter-based) and state the surrogate explicitly.

## H. Compute estimate (the "big compute" to approve)
- Scaled held-out: ~120 payloads x 12 models x 2 (baseline+injected) x K=3 = ~8,640 inferences.
- Adaptive: ~6 strategies x ~5 targets x 12 models x K=8 = ~2,880.
- Multi-turn: ~18 scenarios x 12 models x (single+multi) x K=2 = ~864 (multi-turn calls are longer).
- StruQ baseline: held-out subset (~48) x 12 models x 2 x K=3 = ~3,456.
- Utility + N=7 reals: ~1,000.
- TOTAL ~= 16-17k local inferences. On the M4 at ~2-5 s each, ~10-24 h wall-clock sequential;
  less if batched. Plus ~8 model pulls (download, one-time). No cloud, no API cost.

## I. What changes in the paper after this runs
- Tables I-II (ablation, held-out) gain n + Wilson CIs; new per-model five-axis table with CIs; phi
  reported with bootstrap CI under the pre-registered rule; N=7 becomes a distribution across
  compositions; StruQ row added as a generality check (not a leaderboard); related work restructured
  (P1 #12, done in parallel, no compute).

## Decisions the PI is asked to confirm before compute
1. Model matrix: 6 families x 2 (12 models) as above, or the lean 5x2? Any family swaps
   (e.g., DeepSeek/Command-R/Yi instead of Granite)?
2. Held-out scale: ~120 (5 categories x 24), including the RAG/non-instruction category? Larger/smaller?
3. phi decision rule (D) and the "never assert independence from a point estimate" stance.
4. Baseline framing (G): StruQ-as-generality-check + IsolateGPT/ACE conceptual positioning; confirm we
   do NOT run a prevention leaderboard.
5. Compute budget ~16-17k inferences / ~10-24 h acceptable, or cap it (fewer reps / lean matrix)?
