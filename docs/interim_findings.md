# Interim findings (7 November 2026)

Evidence tiers are kept apart: **[A]** architectural tier with behavioural agents
(model-agnostic); **[M]** measured real component; **[P]** real-LLM pilot (Qwen3.5-4B,
CPU); **[S]** source-reported. All [A] numbers: 8 held-out worlds, 3 % attack
prevalence, 12-week periods, 95 % bootstrap CIs across worlds.

## 1. Loss is bounded by architecture, not by model robustness [A]
Diverted value (DV) per 12-week period at model susceptibility s = 1 (the model pursues
the attacker's goal on every attacked item):

| Config | DV (AED) | 95 % CI | ASR | STP | FHR |
|---|---|---|---|---|---|
| D0 single agent, all tools | 2,465,175 | 2.27M-2.70M | 81.6 % | 94.0 % | 6.3 % |
| D7 naive SoD (two LLMs, free-text hand-off) | 2,465,175 | 2.27M-2.70M | 86.3 % | 94.0 % | 6.3 % |
| D1 spotlighting (adaptive) | 2,202,519 | | 76.9 % | 94.7 % | 5.8 % |
| D1 spotlighting (static) | 1,586,943 | | 59.0 % | 96.0 % | 4.3 % |
| D3 least-privilege tool filtering | 1,225,755 | 1.10M-1.33M | 80.3 % | 98.0 % | 2.1 % |
| D6c controls as an advisory tool | 1,078,531 | | 71.6 % | 94.7 % | 5.5 % |
| D4 CaMeL-style plan-then-execute | 184,005 | 126k-244k | 20.2 % | 97.1 % | 3.3 % |
| **D6 CGA** | **2,740** | **754-6,177** | 6.7 % | **99.4 %** | **0.6 %** |
| D5 human approves every payment | 158 | | 0 % | 0 % | 100 % (28 reviews/day) |

* CGA cuts worst-case DV by 99.9 % against D0 and *raises* STP by 5.4 points
  (poisoned vendor records also break legitimate payments under D0).
* DV(s) for CGA is flat from s = 0.1 to 1 (2.0k-2.7k): **susceptibility invariance**.
  Every model-dependent design grows roughly linearly in s.
* D1's numbers depend on an assumed effect size (60 % static / 10 % adaptive
  reduction) and are labelled as such.

## 2. What remains under CGA is exactly what the proofs predict [A, formal]
* Z3 proves P1 beneficiary integrity, P2 per-invoice and P4 cumulative overpayment
  bounds (duplicates, splitting and re-issues cannot exceed received x PO price x
  (1 + tolerance) x VAT), P3 no payment without receipt; P5 shows the residual
  (overpayment inside price tolerance) is reachable.
* Measured residual: entirely A7 within tolerance (AED ~3k per attack-dense world).
* Adaptive boundary search (60 queries/family): best loss per attempt AED 2,299 under
  CGA (inside tolerance), AED 72,413 (A7) and AED 106,122 (A6) under D4; A8 shell
  companies blocked by onboarding control plus first-payment hold in every design.

## 3. Segregation of duties needs deterministic controls between the sessions [A]
* D7 (maker LLM writes a free-text summary; payer LLM pays) passes the per-session
  Agents Rule of Two yet loses as much as D0: untrusted text crosses the hand-off.
* The Transitive Rule of Two (per-field taint over the workflow graph) flags D7, D4
  (payment.amount uncertified), D6a (beneficiary) and D6b (vendor master), and passes
  only D6 and D5 - matching the measured loss pattern.
* Enforcement beats advice: D6c (same controls, optional) loses 1.08M.

## 4. Controls are redundant in pairs [A]
Removing any single control from CGA is compensated by Verification of Payee (VoP);
removing two is not: no provenance + no VoP 304k; no call-back + no VoP 445k
(609k with a *faithful* maker, because faithfully reported bank-change requests are
auto-applied).

## 5. Risk signals [A, M]
* Triage on the model's own risk estimate cannot help once the model is compromised:
  Loss@B for D0/D4 is identical at B = 2, 5, 10 %.
* The deterministic checker risk score is calibrated (ECE 0.064 -> 0.035 after refit on
  development data); a split-conformal threshold at alpha = 2 % flags 1.2 % of held-out
  benign items and 74 % of attacks.
* Weekly diverted-value-at-risk (95 %): D0 AED 441k (CVaR 483k); D3 210k; CGA 0.

## 6. Channel, prevalence and human reviewers [A]
* All-UBL intake removes PDF-layer attacks and cuts undefended DV by ~21 % (3.33M ->
  2.63M at s = 1) but free-text fields (notes, item descriptions, payment instruction
  notes) keep most of the risk (H3 qualitatively supported).
* DV scales with prevalence for model-dependent designs; CGA stays below AED 11k at
  1-10 %.
* Reviewer error transfers risk: at 10 % reviewer miss rate D4 loses 593k (it escalates
  much more), D5 68k, CGA 28k.

## 7. Real-LLM pilot [P] (Qwen3.5-4B Q4_K_M, 4-core CPU, single-step protocol)
See `results/summary/llm_pilot.json` (pilot still running at the time of writing).
Early D0 records: the model obeyed hidden or embedded instructions on 8 of 11 injected
invoices (A1-A3), often also rewriting the vendor bank account, while reporting a risk
of 0.1. As CGA maker, the same model flagged the instruction and the requested account
change, and the checker held the payment.

## 8. Engineering findings surfaced by the benchmark
* Property-based testing found an absolute rounding slack in the tolerance comparison
  that let low-priced lines exceed the proven bound (invisible to the SMT proof).
* A time-of-check-to-time-of-use race let a near-duplicate be auto-paid while its
  original waited for human review; fixed by reserving matched quantities at
  escalation.
* A real prompt-injection classifier's recall depends on scanning granularity
  (context dilution): 25 % / 69 % / 94 % recall at 512 / 128 / 64-token windows, with
  0 % / 0 % / 40 % false positives on benign twins.
