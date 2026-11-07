# SoD-Bench: Segregation of Duties for AI Agents

Open, laptop-scale procure-to-pay (P2P) sandbox and reference implementation for the
research project *Segregation of Duties for AI Agents: Internal-Control-Grounded
Defences Against Invoice Manipulation and Payment Diversion in Agentic Procure-to-Pay*
(author: Hemanth; supervisor: Prof. Dr. Debashis Guha).

The research proposal is in this repository:
`Segregation_of_Duties_for_AI_Agents_Research_Proposal_Hemanth.docx`.
The working plan and progress log are in [`PLAN.md`](PLAN.md).

## What is here

| Path | Contents |
|---|---|
| `sodbench/world` | Synthetic buying organisation: suppliers, approvers, purchase orders, goods receipts, invoices, credit notes, e-mails, payment runs |
| `sodbench/docs` | Renderers for PDF invoices (with a text layer), UBL 2.1 / Peppol BIS Billing 3.0 / PINT AE-style e-invoices and RFC 5322 e-mails |
| `sodbench/attacks` | Attack families A1-A9 and their benign look-alikes, with development and held-out splits |
| `sodbench/env` | ERP state, agent tools, bank simulator with Verification of Payee, hash-chained audit log |
| `sodbench/controls` | Deterministic controls-as-code: three-way match, duplicate detection, approval matrix, vendor-change protocol, first-payment hold, provenance rule |
| `sodbench/agents` | Behavioural agents (faithful, compromised, stochastic) and LLM agents (llama.cpp or any OpenAI-compatible server) |
| `sodbench/defences` | Defence configurations D0-D6 and ablations D6a-D6c |
| `sodbench/metrics` | Diverted value, attack success, Loss@B, STP, false holds, calibration, DVaR/CVaR, bootstrap and McNemar statistics |
| `sodbench/analysis` | Rule-of-Two and transitive Rule-of-Two analysis, Z3 verification, OpMech order-gap |
| `sodbench/adaptive` | Adaptive attackers with a fixed query budget |
| `experiments` | Scripts that produce every number and figure in the interim report |
| `references` | Verified bibliography (arXiv metadata checked through the arXiv API) |

## Quick start

```bash
pip install -e .
python -m pytest -q
python experiments/run_grid.py --quick
```

All content is synthetic. Names, tax identifiers and bank accounts are invented;
account numbers are checksum-valid but fictitious. No real payment or ERP system is
touched. Attack templates are released for defensive research on this sandbox only.

## Honesty conventions

Every table separates (1) architectural results with behavioural agents, (2) measured
real components, (3) real-LLM pilot results and (4) source-reported numbers from prior
work. Source-reported numbers are never presented as results of this project.
