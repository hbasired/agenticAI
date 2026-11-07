# SoD-Bench research plan and progress log

This file tracks how the research proposal
(`Segregation_of_Duties_for_AI_Agents_Research_Proposal_Hemanth.docx`, 30 Oct 2026)
is being turned into code, experiments and the interim report. It is updated at
every commit so the repository history doubles as a lab notebook.

## Scope of the interim phase

The proposal's twelve-week plan (Table 12) starts on 2 Nov 2026. The interim phase
covers the build work of weeks 1 to 6 and a first, honest set of measurements:

| Proposal deliverable | Interim status target |
|---|---|
| Generator v0, 50 hand-checked scenarios, data card (wk 1-2) | Generator, scenario validator, data card, Croissant stub |
| Tools, benign suite, baselines D0-D3, measured compute profile (wk 3-4) | Tool layer, benign suite, D0-D3, CPU compute profile |
| Attack families A1-A9 with benign look-alikes; CGA; unit-tested controls (wk 5-6) | All nine families, CGA (D6) and ablations, unit and property tests |
| Main grid, D4, e-invoice channel study (wk 7-8) | Model-agnostic grid now; real-LLM grid scripted for Colab/Kaggle |
| Adaptive attacks, OpMech ablation (wk 9-10) | Adaptive search against controls and against a real detector; OpMech harness and CPU pilot |

## Evaluation tiers (kept strictly apart in every table)

1. **Architectural (model-agnostic) tier.** The language model is replaced by
   behavioural agents that span the space of possible model behaviour: a *faithful*
   clerk, a *fully compromised* maker that obeys every injected instruction (the
   worst case, analogous to a Byzantine participant), and a *stochastic* agent whose
   susceptibility `s` is swept from 0 to 1. Results here are properties of the
   architecture and controls, not of any model.
2. **Measured-component tier.** Real components measured on SoD-Bench content,
   e.g. an open-weight prompt-injection classifier as the D2 detector, and an
   adaptive search against that detector.
3. **Real-LLM pilot tier.** Qwen3.5-4B (Apache-2.0, Q4_K_M GGUF) running on a
   4-core CPU through llama.cpp. Small samples, reported with confidence intervals
   and labelled as a pilot.
4. **Source-reported tier.** Numbers from prior literature, never mixed with ours.

## Novel elements added beyond the proposal

- **Compromised-maker bound and susceptibility curves.** Diverted value as a
  function of model susceptibility, `DV(s)`; an architecture is *susceptibility-
  invariant* when `dDV/ds` is close to zero. This yields guarantees that do not
  depend on how robust current or future models are.
- **Clark-Wilson grounding.** The language model is treated as an *uncertified
  transformation procedure* that may only produce unconstrained data items; only
  certified, deterministic code may write constrained data items (vendor master,
  payment queue). The provenance rule is Clark-Wilson's certification rule for
  unconstrained inputs.
- **Transitive Rule of Two (TRo2).** A taint-reachability check over the whole
  agent workflow graph, closing the gap where per-session Rule-of-Two compliance
  is defeated by cross-agent notes or shared memory (attack family A9).
- **Machine-checked controls.** SMT (Z3) proofs and property-based tests of the
  beneficiary-integrity invariant and the overpayment bound of the checker.
- **Finance-native risk metrics.** Diverted-value-at-risk (DVaR) and conditional
  DVaR over simulated periods, loss-exceedance curves, attacker return on effort.
- **Conformal escalation.** Distribution-free control of the false-hold rate at a
  fixed review budget.

## Progress log

- 2026-11-07: Repository initialised on branch `claude/sod-bench`. 92 arXiv
  references verified through the arXiv API (`references/arxiv_meta.json`),
  including all 25 arXiv references of the proposal. Closest 2026 prior work
  identified (governed-execution SoD for OS agents; organisational control layer;
  payment-authorisation benchmarks; AP2 attacks). Qwen3.5-4B runs on the CPU.
- 2026-11-07: SoD-Bench v0 built: world generator, nine attack families with
  benign twins and dev/held-out splits, PDF/UBL/e-mail renderers, ERP state with
  hash-chained audit log, controls-as-code checker, configurations D0-D7, money-
  denominated scoring. 10 unit and property tests pass. Z3 proofs P1-P5 and the
  transitive Rule-of-Two analysis added. Architectural grid (~1,400 episodes),
  prevalence, channel, review-budget and reviewer-error sweeps, adaptive boundary
  search, real-detector scoring and the Qwen3.5-4B CPU pilot run. Bibliography
  grown from 52 to 174 entries (`references/bibliography.py`).
- Engineering findings surfaced by the benchmark itself and fixed: an absolute
  rounding slack in the price-tolerance comparison (found by property-based
  testing, invisible to the SMT proof of the abstract model); a time-of-check-to-
  time-of-use race in which a near-duplicate could be auto-paid while the original
  waited for human review (fixed by reserving matched quantities at escalation).
- 2026-11-07 (evening): Benchmark targets pre-registered (docs/benchmarks.md,
  commit 3655400) before the confirmatory campaign. Realism condition added
  (agreed supplier surcharges in vendor tolerance groups). Three frozen CGA
  versions evaluated once each on ten fresh held-out worlds: v0.1 (global 2 %
  tolerance) fails X3; v0.2 (pay PO price, all variances to the buyer) fails X2,
  O1, O2, O3, O6; v0.3 (vendor tolerance groups + deterministic UBL parsing)
  passes all fifteen targets and the robustness sweep. Development-world results
  and every evaluation are in results/benchmark_ledger.csv. Bibliography grown to
  299 entries (150 from 2025-2026). Interim report generated from scratch in the
  proposal's format: report/output/.

