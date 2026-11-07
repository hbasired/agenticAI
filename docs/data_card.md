# SoD-Bench data card (v0.1, interim)

Structured after *Datasheets for Datasets* (Gebru et al., 2021). Machine-readable
metadata: [`data/croissant.json`](../data/croissant.json) (Croissant 1.0).

## Motivation
SoD-Bench measures, in money, how much an attacker who controls only supplier-facing
content can divert from an LLM-agent-operated procure-to-pay (P2P) process, and which
defences bound that loss. Real accounts-payable data is confidential and its fraud
labels are incomplete; a synthetic world gives exact ground truth.

## Composition
One buying organisation (Meridian Components Trading LLC, fictional, AED, VAT 5 %)
over 12 business weeks (60 days) per world:

| Entity | Typical count per world | Notes |
|---|---|---|
| Suppliers | 300 (+6 onboarded during the period) | checksum-valid fictitious IBANs (bank codes 901-908), Luhn-valid synthetic TRNs, `.example` domains |
| Purchase orders | ~1,500 | 1-3 lines from category catalogues, heavy-tailed supplier activity |
| Goods receipts | ~1,800 | full (72 %), partial (18 %), short (7 %), with return (3 %) |
| Inbox items | ~1,900 | invoices (PDF by e-mail ~55 %, UBL/PINT AE ~45 %), credit notes, routine e-mail |
| Attacks | 1-10 % of inbox (default 3 %) | nine families A1-A9 (see `sodbench/attacks/families.py`) |
| Benign twins | ~1 per attack | share surface features of each family |

Ground truth per item: payee supplier, legitimate value, attacker account and goal,
family, template id and split. Entitlement for scoring is computed per PO line from
goods actually received (net of returns, priced at the PO price incl. amendments).

## Splits
*Development* and *held-out* splits differ in injection phrasings (8 + 8), BEC,
re-issue, onboarding and laundering templates (2-3 + 2-3 each), look-alike-domain
transformations, near-duplicate number mutations, inflation ranges, attacker banks
(905/906 vs 907/908) and targeted supplier pools (odd vs even supplier ids).
All headline numbers use held-out worlds.

## Collection process
Fully procedural (`sodbench/world/generator.py`), seeded and deterministic. Formats
follow public standards: UBL 2.1, Peppol BIS Billing 3.0 and a PINT AE-style profile
(CustomizationID `urn:peppol:pint:billing-1@ae-1`, endpoint scheme 0235), RFC 5322
e-mail, ISO 13616 IBAN structure. PDFs are rendered with ReportLab and read back with
pypdf so that hidden text reaches agents through a real text-layer extractor.

## Uses
Intended: defensive evaluation of agent architectures and controls for P2P. Not
intended: training fraud tooling, testing or probing real products, or any inference
about real companies (all names are invented; any resemblance is coincidental).

## Known limitations
Synthetic suppliers and documents do not capture every real-world behaviour; the
human reviewer is modelled as resolving reviewed items correctly unless an error rate
is set; insider fraud, ERP compromise and attacks on the call-back channel itself are
out of scope; the LLM pilot uses a single-step protocol (lookups pre-fetched).

## Distribution and maintenance
Released with the code under the licence chosen by the author (to be decided before
publication). Worlds are regenerated from seeds; no personal data is included.
