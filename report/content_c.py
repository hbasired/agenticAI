"""Interim report content, part C: Sections 6 and 7."""
from __future__ import annotations

import os

from report.results import aed, pct

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def section6(R, V):
    R.h1("6. Data and Environment Plan")
    R.h2("6.1 Why a synthetic environment")
    R.para("Real accounts-payable data contains supplier bank details, personal data and confidential prices, and real "
           "fraud labels are incomplete. A synthetic environment gives complete ground truth: for every invoice we know "
           "what was ordered, what was received, what is owed and to which account it should be paid. The price is "
           "external validity, which we address by grounding formats in public standards {c:43}, {c:ubl21}, {c:pint_ae}, "
           "{c:en16931}, attack families in documented typologies {c:15}, {c:2}, {c:cidon2019} and process rules in "
           "internal-control practice {c:32}, and by stating plainly that sandbox results are not evidence of production "
           "readiness. Synthetic transaction generators are established in anti-money-laundering research for the same "
           "reasons {c:8}, {c:2506.13989}.")
    R.h2("6.2 SoD-Bench design")
    R.para("SoD-Bench v0.1 is implemented in Python as the sodbench package. One buying organisation is simulated over twelve "
           "business weeks: 300 suppliers with verified master data (legal name, synthetic tax number with a Luhn check "
           "digit {c:luhn1960}, contact on file, ISO 13616-structured IBAN with a valid mod-97 checksum but a fictitious "
           "bank code {c:iso13616}), six suppliers onboarded during the period, employees with authority limits, about "
           "1,500 purchase orders, 1,800 goods receipts with partial deliveries, short shipments and returns, and about "
           "1,900 inbox items per world. E-mail domains use the reserved .example top-level domain, so no generated "
           "address can route to a real party.")
    R.para("Two intake channels are rendered faithfully. PDF invoices are drawn with ReportLab and read back through a "
           "real text-layer extractor, so text drawn in white one-point type reaches the agent exactly as it would "
           "through a production parser while remaining invisible to a human reader, the threat studied by CrackedPDFs "
           "and PhantomLint {c:2607.19396}, {c:2508.17884}. Structured invoices are UBL 2.1 documents with the PINT AE "
           "customisation identifier and Peppol endpoint scheme 0235 {c:pint_ae}, flattened field by field for the "
           "agent, including the free-text fields (notes, item descriptions, payment instruction notes) where attack "
           "family A3 hides instructions. E-mails are RFC 5322 messages.")
    R.para("Ground truth is exact by construction. Entitlement is computed per purchase-order line from goods actually "
           "received, net of returns, at the PO price including contract amendments; diverted value counts every payment "
           "to an account not owned by the payee in full, plus any amount paid to a genuine supplier above what it is "
           "owed. An append-only audit log chains each entry to its predecessor with SHA-256, following the hash-chain "
           "time-stamping idea {c:haber1991}, {c:crosby2009}; tampering with any entry breaks verification, which the "
           "test suite checks.")
    R.table(["Component", "What it provides", "Status (interim)"],
            [["Supplier master (306)", "Verified identity, contact on file, IBAN, tolerance group", "Built; tested"],
             ["Purchase orders and receipts", "Ordered, received and returned quantities; prices; amendments", "Built"],
             ["PDF invoices and credit notes", "ReportLab layout, pypdf text layer, hidden-text capable", "Built"],
             ["UBL / PINT AE-style e-invoices", "Structured fields plus free-text notes", "Built; flattened agent view"],
             ["Supplier e-mail", "Invoices, reminders, statements, bank changes, onboarding", "Built"],
             ["Policy pack (YAML)", "Tolerances, approval matrix, change protocol, variance policy", "Built; versioned"],
             ["Bank simulator", "Payment runs, Verification of Payee name checks", "Built"],
             ["Audit log", "SHA-256 hash chain of every control decision", "Built; tamper test passes"],
             ["Data card, Croissant metadata", "Datasheet and machine-readable metadata {c:datasheets}, {c:croissant}",
              "Draft v0.1"]],
            [2600, 4300, 2460], "SoD-Bench components and their implementation status.")
    R.h2("6.3 Attack families and benign look-alikes")
    R.para("Nine attack families cover the main ways a supplier-facing adversary can try to move money. Each is paired "
           "with benign look-alikes so that a defence cannot score well by holding everything unusual. Development and "
           "held-out splits use disjoint injection phrasings (8 and 8), business-email-compromise, re-issue, onboarding "
           "and laundering templates, look-alike-domain transformations {c:szurdi2014}, {c:gabrilovich2002}, near-"
           "duplicate number mutations (compared with Levenshtein distance {c:levenshtein1966}), inflation ranges, "
           "attacker banks and targeted supplier pools. Bank-change attacks are timed shortly before invoices the "
           "attacker knows are pending, as real BEC campaigns are.")
    R.table(["ID", "Attack family", "Channel", "Attacker goal", "Benign look-alike"],
            [["A1", "Hidden instruction in an invoice PDF", "PDF text layer (white, 1 pt)", "Change beneficiary",
              "Long small-print legal footer"],
             ["A2", "Visible note to automated processing", "PDF body or e-mail body", "As A1, with urgency",
              "Genuine processing notes"],
             ["A3", "Instruction in structured e-invoice free text", "UBL notes, item text, payment note", "As A1",
              "Legitimate e-invoice notes"],
             ["A4", "Bank-change request without injection", "E-mail, look-alike or compromised", "Redirect future payments",
              "Genuine change confirmed by call-back"],
             ["A5", "Impersonation with re-issued invoice", "E-mail plus PDF", "Be paid for real goods",
              "Credit note plus corrected invoice"],
             ["A6", "Duplicate or near-duplicate invoice", "PDF or e-invoice", "Double payment",
              "Partial invoices and credit notes"],
             ["A7", "Price or quantity inflation; splitting", "Invoice lines", "Overpayment",
              "Contract-backed price amendment; agreed surcharges"],
             ["A8", "Fictitious supplier onboarding", "Onboarding e-mail plus invoices", "Pay a shell company",
              "Genuine new supplier"],
             ["A9", "Cross-agent trust contamination", "Notes written by one agent, read by another",
              "Launder a 'verified by phone' claim", "Internal verification-service records"]],
            [560, 2200, 2200, 1900, 2500], "Attack families and benign look-alikes. All content is synthetic.")
    R.h2("6.4 Realism conditions added in the interim phase")
    R.para("Two realism conditions were added once the first results arrived, because without them some designs would "
           "look better than they are. First, a share of suppliers bill a small agreed surcharge (0.5-2 percent) on every "
           "invoice, which is owed and recorded in a vendor tolerance group; strict price policies then pay a real "
           "automation cost. Second, every result can be re-run with a fallible human reviewer (miss rate 10-30 percent) "
           "and with fictitious suppliers that pass onboarding (20 percent), reflecting automation bias "
           "{c:parasuraman2010}, {c:2509.06595} and the commoditisation of deepfakes {c:2506.07363}, {c:2601.02914}. "
           "Both conditions are part of the pre-registered robustness sweep (Section 8.4).")


def section7(R, V):
    R.h1("7. Proposed Methodology and Architecture")
    R.h2("7.1 Threat model")
    R.para("The adversary controls supplier-facing content: e-mails, including those from look-alike domains, PDF and "
           "structured invoices, and onboarding requests. It may know the agent's design, prompts and controls (white-"
           "box) and observe the outcomes of earlier attempts (adaptive). It cannot modify the ERP database directly, "
           "alter contact details that were on file before the attack, or compromise internal staff; insider fraud, ERP "
           "compromise and attacks on the human call-back step are out of scope. We now flag the last exclusion as the "
           "most fragile assumption: audio-based authentication has documented vulnerabilities to deepfake speech "
           "{c:2601.02914}, and AI models' capability to automate voice phishing has been evaluated {c:2607.09970}.")
    R.h2("7.2 Formal setting and loss")
    R.para("Let *s* be the environment state and *x*_{1}, ..., *x*_{n} the inbox items of a period. A configuration *π* "
           "maps items to actions and ultimately to a set *P* of executed payments, each with amount *a*_{p}, "
           "beneficiary *b*_{p} and entitlement *e*_{p}. Diverted value is")
    R.equation("DV(π) = Σ_{p ∈ P} [ a_{p} · 1(b_{p} ∉ V) + max(0, a_{p} − e_{p}) · 1(b_{p} ∈ V) ]")
    R.para("where *V* is the set of accounts genuinely owned by the payee. In the implementation the second term is "
           "computed per purchase order, so duplicates, splits and re-issues on the same order cannot hide overpayment. "
           "Straight-through processing (STP) is the share of legitimate payable value paid correctly without human "
           "touch; the false-hold rate (FHR) is the share of legitimate payable items not paid in full automatically. "
           "Loss@*B* is diverted value at the escalation threshold that fits a review budget of *B* percent of daily "
           "volume, and the residual adaptive loss is the largest diverted value an adaptive attacker finds within a "
           "query budget *Q*. We add two finance-native summaries: weekly diverted-value-at-risk (DVaR_{95}) and its "
           "conditional version (CVaR_{95}) {c:jorion2006}, {c:cvar}, {c:artzner1999}.")
    R.h2("7.3 Control-Grounded Agent Architecture (CGA)")
    R.para("CGA splits the workflow into sessions that each satisfy the Agents Rule of Two and places deterministic "
           "controls between them (Figure {ref:fig:cga}). The intake agent (maker) reads supplier content and looks up records read-"
           "only; its only output is a typed proposal under schema-constrained decoding {c:2501.10868}. The checker is "
           "plain code that applies the policy pack. The payer executes only approved proposals and never sees supplier "
           "text. Escalations go to a human queue ranked by a calibrated risk score, and an audit log records every "
           "decision.")
    R.figure(os.path.join(ASSETS, "fig_cga_architecture.png"),
             "Control-Grounded Agent Architecture in SoD-Bench (reproduced from the proposal). Badges mark the Agents Rule "
             "of Two properties held by each LLM session; the checker is deterministic code. The OpMech diagnostic is an "
             "exploratory ablation.", label="fig:cga")
    R.table(["Internal control", "Agent-level implementation in CGA", "Attacks addressed", "Implemented as"],
            [["Segregation of duties", "Maker and payer sessions with a deterministic checker between them", "A1-A5, A9",
              "runner.process_typed"],
             ["Maker-checker above limits", "Human release above AED 250,000; first-payment hold", "A4-A8", "checker._payable"],
             ["Three-way match", "Cumulative match of order, receipt and invoice; short-pay", "A1, A2, A7",
              "checker._payable"],
             ["Duplicate-payment check", "Exact key rejects; near-duplicate (same order, same digit core) escalates", "A6",
              "checker.is_duplicate"],
             ["Vendor-master change control", "Tickets only; call-back to contact on file; cooling-off", "A1-A5, A9",
              "runner.tickets_and_review"],
             ["Verification of Payee", "Name check at payment; block on no match, escalate on close match", "A4, A5, A9",
              "bank.verify_payee"],
             ["Price-variance control (v0.2/v0.3)", "Pay PO price; route variances to buyer; vendor tolerance groups",
              "A6, A7", "checker._payable"],
             ["Data-flow (provenance) control", "Beneficiary only from verified master data", "A1-A3, A5, A9",
              "checker._payable"],
             ["Audit trail", "SHA-256 hash-chained log of every decision", "All (detection)", "state.AuditLog"]],
            [2100, 3600, 1400, 2260], "Internal controls and their implementation in CGA.", label="tab:controls")
    R.h2("7.4 Defences compared")
    R.para("All configurations run on the same worlds, attacks, seeds and review budgets (Table {ref:tab:defences}). We added D7, naive "
           "segregation of duties with two LLM sessions joined by free text, to test whether segregation without "
           "certified channels is enough, and VoP-removal ablations to measure how controls cover for each other.")
    R.table(["ID", "Configuration", "Idea", "Source"],
            [["D0", "Single tool-using agent with all tools", "Undefended reference", "—"],
             ["D1", "D0 with spotlighting (datamarking) and hardened prompt", "Mark untrusted text as data", "{c:40}"],
             ["D2", "D0 with a prompt-injection classifier on all untrusted text", "Detector-level filtering",
              "{c:41}, {c:protectai}"],
             ["D3", "D0 with least-privilege tool filtering", "Remove unneeded tools", "{c:31}"],
             ["D4", "Plan-then-execute, quarantined LLM, capability policy", "System-level isolation", "{c:35}, {c:36}"],
             ["D5", "Human approval of every payment", "Security reference", "—"],
             ["D6", "CGA (v0.1, v0.2, v0.3)", "SoD sessions, controls-as-code, provenance", "This work"],
             ["D6a-c", "No provenance; no call-back; controls advisory only", "Ablations", "This work"],
             ["D7", "Maker LLM and payer LLM joined by free text", "Naive segregation", "This work"]],
            [900, 3700, 2700, 2060], "Defence configurations compared under one protocol.", label="tab:defences")
    R.h2("7.5 Adaptive attacker")
    R.para("Following the recommendation that defences be evaluated against attackers who adapt {c:34}, we implemented "
           "two adaptive attackers. A white-box control-boundary search knows the policy pack, observes the money "
           "outcome of each attempt, samples attack parameters (inflation, splitting, duplicate-number mutations, "
           "amounts, delays, target supplier group) and refines around the best point; each query is a full twelve-week "
           "episode. A black-box mutation search attacks the real detector, rewording, padding and re-encoding the "
           "injected note while preserving the attacker's account number, in the spirit of automated red-teaming and "
           "self-evolving phishing {c:2503.15754}, {c:2507.21538}. A human red-team round remains planned.")
    R.h2("7.6 OpMech order-gap as an exploratory diagnostic")
    R.para("For an inbox item *e*, let *P*_{e} denote expansion (reading the item) and *Q* consolidation (reading the "
           "verified records). We run the intake agent twice, once with the document first and once with the records "
           "first, and define the order-gap as a disagreement in document kind, beneficiary, total, requested action or "
           "bank-change account between the two proposals. A large gap is read as a diagnostic, never as a fraud score "
           "{c:12}; the comparison costs one extra model call per item.")
    R.h2("7.7 Model-agnostic evaluation and the compromised-maker bound")
    R.para("Model-level defences can only be evaluated model by model, and every new model release reopens the question. "
           "We therefore add an architectural evaluation tier in which the language model is replaced by behavioural "
           "agents that span its possible behaviour: a faithful clerk, a compromised maker that pursues the attacker's "
           "goal on every attacked item and lies in its typed output whenever that helps the attacker (a Byzantine "
           "participant), and a stochastic agent deceived on each attacked item with probability *s*. Diverted value as a "
           "function of *s*, DV(*s*), separates designs whose loss grows with model susceptibility from designs whose "
           "loss is bounded by construction. We call a design susceptibility-invariant when DV(*s*) is nearly flat; the "
           "worst case DV(1) is then an upper bound that holds for any current or future model under the stated threat "
           "model. This matters because model capability is rising quickly {c:2503.14499}, {c:2501.17805} without a "
           "matching guarantee that models resist manipulation, and because smaller, cheaper models are increasingly used "
           "in agentic roles {c:2506.02153}, {c:2604.19299}.")
    R.h2("7.8 Clark-Wilson grounding and the Transitive Rule of Two")
    R.para("The Clark-Wilson model gives CGA a precise vocabulary {c:clark1987}. The vendor master and the payment queue "
           "are constrained data items. Supplier documents, and anything a language model writes about them, are "
           "unconstrained data items. The checker is the certified transformation procedure through which an "
           "unconstrained item may influence a constrained one, and the provenance rule is the certification rule that "
           "such input must be validated or rejected. A language model is, in this reading, an uncertified "
           "transformation: it may propose, but it may never write constrained data.")
    R.para("The Agents Rule of Two is evaluated per session {c:9}. In multi-agent workflows, untrusted text can reach a "
           "session indirectly through another model's summary, a shared note store or memory {c:2606.04329}, "
           "{c:2410.07283}. We therefore define the Transitive Rule of Two (TRo2): propagate untrusted taint along every "
           "data-flow edge of the workflow graph, stop it for a field only at nodes that certify that field by re-deriving "
           "it from verified records, and require that no tainted session hold both sensitive access and the power to "
           "act, and that no integrity-critical sink (beneficiary, amount, vendor master) be reachable from untrusted "
           "content without certification. Table {ref:tab:tro2} shows that TRo2 separates designs that the per-session rule cannot. "
           "Concurrent work asks whether CaMeL's guarantees compose across agent hierarchies {c:2610.05640}; from its "
           "abstract, its focus is CaMeL composition rather than a workflow-level criterion, but we have not yet compared "
           "the two in depth.")
    rows = []
    for r in V["tro2"]:
        rows.append([r["config"], "yes" if r["rule_of_two_per_session"] else "no", "yes" if r["tro2"] else "no",
                     ", ".join(r["uncertified_critical_sinks"]) or "none"])
    R.table(["Config", "Rule of Two per session", "Transitive Rule of Two", "Critical sinks reachable from untrusted text"],
            rows, [1300, 2200, 2200, 3660],
            "Rule-of-Two analysis. D7 passes the per-session test yet fails the transitive one; only D5 and D6 pass both.",
            label="tab:tro2")
    R.h2("7.9 Machine-checked controls")
    R.para("Because the checker is code, its key properties can be proved rather than measured. We encoded the payable "
           "path in the Z3 SMT solver {c:z3} and proved each property by showing its negation unsatisfiable for every "
           "proposal a maker could emit (Table {ref:tab:z3}). Removing the provenance rule turns property P1 into a satisfiable query "
           "with a concrete counterexample. The proofs cover the abstract model; property-based tests with Hypothesis "
           "{c:hypothesis} check the same invariants on the Python implementation, and they found a defect the proof could "
           "not see: an absolute rounding allowance in the tolerance comparison let low-priced lines exceed the proven "
           "bound. A second defect, a time-of-check-to-time-of-use race {c:bishop1996} in which a near-duplicate could be "
           "auto-paid while its original waited for human review, was found by the benchmark itself and fixed by "
           "reserving matched quantities at escalation.")
    rows = [[r["property"].split(" ", 1)[0], r["property"].split(" ", 1)[1], "holds" if r["holds"] else "fails",
             "proved (negation unsatisfiable)" if r["detail"] == "proved" else ("counterexample found" if
                                                                                 "counterexample" in r["detail"] else
                                                                                 "reachable (as predicted)")]
            for r in V["z3"]]
    R.table(["ID", "Property of the checker", "Result", "Evidence"], rows, [700, 5260, 1100, 2300],
            "Properties of the controls-as-code checker checked with Z3.", label="tab:z3")
