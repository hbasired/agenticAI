"""Interim report content, part A: front matter and Sections 1-4.

Citations are written as {c:key}; keys 1-52 are the proposal's references, other keys
are entries of references/bibliography.py. Numbers in the text come from report/results.py.
"""
from __future__ import annotations

from report.results import aed, pct


def front(R, V):
    g = V["grid"]
    dv0 = g.loc[("D0", 1.0), "DV"]
    dv6 = g.loc[("D6", 1.0), "DV"]
    R.title_page(
        "Segregation of Duties for AI Agents",
        "Internal-Control-Grounded Defences Against Invoice Manipulation and Payment Diversion in Agentic Procure-to-Pay",
        "Interim Report",
        "Note: the OpMech order-gap diagnostic is treated as an exploratory ablation, not as a proven defence.",
        ["Author: Hemanth", "Class: MAIB March 2025",
         "Project area: Agentic AI in Supply Chain Finance and Financial Controls",
         "Supervisor: Prof. Dr. Debashis Guha",
         "Primary environment: SoD-Bench, an open synthetic procure-to-pay sandbox built for this study",
         "Target venue: USENIX Security '27, Cycle 2 (submission due 26 January 2027)",
         "Date: 7 November 2026",
         f"Code and data: github.com/hbasired/agenticAI, branch claude/sod-bench (commit {V['commit']})"],
        ["This interim report keeps four kinds of evidence strictly apart, and every table says which kind it shows: "
         "(A) architectural results, in which the language model is replaced by behavioural agents that span possible "
         "model behaviour; (M) measurements of real software components; (P) a small real-model pilot with an open-"
         "weight 4-billion-parameter model on a laptop-class CPU; and (S) numbers reported by other authors.",
         "Source-reported numbers are never presented as our own. Results from synthetic worlds are not evidence of "
         "production readiness. Where we are not certain of a fact or a reading of prior work, we say so in the text."])
    R.h1("Abstract")
    R.para("Accounts payable is where a supply chain turns into money, and it is being handed to AI agents. The fraud "
           "that most often targets this workflow, business email compromise, produced losses of roughly USD 3 "
           "billion reported to the FBI in 2025 (source-reported {c:2}; secondary summaries differ slightly, so the "
           "primary report should be consulted). An accounts-payable agent reads untrusted documents, touches vendor "
           "and ledger data and changes financial state, which is the combination that agent-security guidance warns "
           "against {c:9}, {c:trifecta}. This interim report tests whether internal controls, re-expressed as agent "
           "architecture and enforced as deterministic controls-as-code, bound the money a manipulated agent can divert.")
    R.para(f"We built SoD-Bench, an open procure-to-pay sandbox with purchase orders, goods receipts, PDF and UBL / "
           f"PINT AE-style e-invoices, supplier e-mail and weekly payment runs, seeded with nine attack families and "
           f"benign look-alikes, and implemented eleven defence configurations, including the proposed Control-Grounded "
           f"Agent Architecture (CGA). In the architectural tier, a fully compromised model diverts {aed(dv0)} per "
           f"twelve-week period from an undefended agent and {aed(dv6)} from CGA, while CGA keeps the highest "
           f"straight-through processing (STP) of all designs. CGA's loss is nearly flat in model susceptibility, so "
           f"the bound does not depend on how robust today's or tomorrow's models are. Z3 proofs, property-based tests, "
           f"a transitive extension of the Agents Rule of Two, a real prompt-injection classifier, adaptive attackers "
           f"and a pre-registered benchmark campaign support and qualify this result; a real-model pilot with "
           f"Qwen3.5-4B shows the same pattern on a small sample.")
    R.h2("Keywords")
    p = R.para("Agentic AI; procure-to-pay; accounts payable; prompt injection; business email compromise; internal "
               "controls; segregation of duties; Clark-Wilson integrity; information-flow control; Rule of Two; "
               "controls-as-code; formal verification; e-invoicing; supply chain finance; open-weight models.")
    R.page_break_in(p)
    R.contents_placeholder()


def section1(R, V):
    g = V["grid"]
    red = 1 - g.loc[("D6", 1.0), "DV"] / g.loc[("D0", 1.0), "DV"]
    R.h1("1. Executive Summary")
    R.para("This study asks a practical question on the seam between supply chain management and finance: when a large "
           "language model (LLM) agent processes supplier invoices and prepares payments, how much money can an attacker "
           "who controls only documents and e-mails divert, and which defences bound that loss? The proposal of 30 "
           "October 2026 committed to measuring the answer in currency rather than assuming it. Six weeks of planned "
           "build work have been compressed into this interim phase: the benchmark, the defences, the analysis tools "
           "and a first round of measurements now exist, and the evidence is reported with its tier and its conditions.")
    R.para(f"The headline is architectural. With a model that pursues the attacker's goal on every attacked item, CGA "
           f"reduces diverted value by {pct(red, 2)} against an undefended single agent on the same worlds, and raises "
           f"rather than lowers straight-through processing, because a poisoned vendor record also breaks legitimate "
           f"payments in the undefended design. The reduction comes from where controls sit, not from a better model: "
           f"the beneficiary account can only come from verified master data, quantities and prices are re-derived "
           f"from orders and receipts, and every vendor-master change waits for a call-back to a contact already on "
           f"file {c(32)}. Machine-checked proofs show that no proposal a model could emit escapes these bounds, and "
           f"the residual loss is exactly the one the proofs predict: overpayment inside price tolerances.")
    R.para("Three further findings matter for practice. First, segregating duties between two LLM sessions is not "
           "enough: a design whose maker and payer are both models, joined by free text, passes the per-session Rule of "
           "Two {c:9} and still loses as much as the undefended agent; a transitive version of the rule detects this. "
           "Second, the real prompt-injection classifier we deployed caught only a small share of injected items and was "
           "evaded by every adaptive mutation search it faced, matching the warning of Nasr et al. {c:34}. Third, "
           "routing items to humans by the model's own risk estimate does nothing once the model is deceived. Each "
           "finding, with its conditions and its limits, is in Section 8.")
    R.para("We also set benchmarks before running the confirmatory campaign, as requested by the supervisor-facing plan "
           "and in line with pre-registration practice {c:nosek2018}: hypotheses H1-H4 from the proposal, five external "
           "reference points from other benchmarks (flagged as not like-for-like), six operational targets for an "
           "accounts-payable function and three real-model targets. Three frozen CGA versions were evaluated once each "
           "on fresh held-out worlds; Section 8.8 lists which targets each version beats and under which conditions.")


def c(n):
    return f"{{c:{n}}}"


def section2(R, V):
    R.h1("2. Real-World Problem Scan and Topic Selection")
    R.h2("2.1 What is going wrong in 2025–2026")
    R.para("Agentic AI in supply chains is still in a test-and-learn phase. A November 2025 survey of North American "
           "transportation, logistics and supply chain executives found 42 percent of organisations not yet exploring "
           "agentic AI at all (source-reported {c:13}), Boston Consulting Group argues that AI decisions in supply chains "
           "must be transparent, auditable and explainable {c:14}, and Gartner expects more than 40 percent of agentic AI "
           "projects to be cancelled by the end of 2027 for reasons that include inadequate risk controls {c:5}. "
           "Benchmarks of agents acting as inventory managers and enterprise decision-makers report systematic decision "
           "biases {c:2508.11416}, {c:2609.37658}. Trust and control, rather than raw capability, remain the binding "
           "constraint.")
    R.para("Payments fraud is persistent and is being industrialised by the same models. The Association for Financial "
           "Professionals reports that 76 percent of U.S. organisations experienced attempted or actual payments fraud in "
           "2025 {c:1}, billing schemes account for 22 percent of occupational fraud cases {c:15}, and the FBI's 2025 "
           "report, released in April 2026, was the first to break out AI-related complaints as a category (source-"
           "reported {c:2}). Research has measured LLMs' ability to run fully automated spear-phishing {c:2412.00586} and "
           "voice-phishing {c:2607.09970} campaigns, to evolve phishing adaptively {c:2507.21538}, and to clone voices well "
           "enough to defeat audio authentication {c:2601.02914}, {c:2506.07363}. Accounting staff are a documented "
           "target group {c:2511.22189}. The last point matters directly for this study, because call-back verification, "
           "one of the controls we rely on, assumes the voice on the phone is genuine.")
    R.para("Agents are now arriving in exactly this workflow, and attacks on them have moved from proofs of concept to "
           "systematic studies. Microsoft's Payables Agent ingests vendor invoices from mailboxes {c:3}; EchoLeak showed "
           "a zero-click prompt-injection exploit in a production assistant {c:4}; real-world e-mail agents have been "
           "hijacked through their inboxes {c:2507.02699}, {c:2609.30657}; hidden instructions in PDFs now have their own "
           "benchmark and detectors {c:2607.19396}, {c:2508.17884} and have appeared in academic peer review "
           "{c:2512.23684}; and the OWASP agentic top ten lists goal hijack and tool misuse first {c:17}. In 2026 the "
           "first payment-specific agent studies appeared: an authorisation benchmark replaying thousands of human-"
           "written attacks against a payment agent {c:2609.22076}, attacks that make agent payment protocols sign "
           "carts the user never chose {c:2609.11757}, and hardening of HTTP-native agent payments {c:2604.11430}.")
    R.para("Infrastructure and governance are shifting at the same time; because these developments are recent, we "
           "cite the documents we could retrieve in November 2026 and recommend checking them for later revisions. "
           "Verification of Payee is mandatory for euro-area payment service providers since 9 October 2025 {c:18}; "
           "the UAE's PINT AE e-invoicing standard {c:pint_ae} is phased in from 2026-2027 {c:19}, {c:20}; the EU's VAT "
           "in the Digital Age package mandates structured e-invoicing for intra-EU trade later in the decade {c:vida}. "
           "Agent payment protocols such as AP2 {c:ap2}, the Agentic Commerce Protocol {c:acp} and Visa's Trusted Agent "
           "Protocol {c:visa_tap} launched in late 2025. COSO issued guidance on internal control over generative AI in "
           "February 2026 {c:coso_genai}, and NIST's Center for AI Standards and Innovation opened an AI Agent Standards "
           "Initiative after a request for information on agent security {c:nist_caisi}, together with design tenets for "
           "agent identity that name separation of duties and least privilege {c:nist_identity}.")


def section3(R, V):
    R.h1("3. Introduction")
    R.para("Procure-to-pay (P2P) is the chain through which an organisation buys and pays: a requisition becomes a purchase "
           "order, goods are received, the supplier invoices, the invoice is matched against order and receipt, an "
           "authorised person approves, and a payment run releases funds. Finance wraps this chain in internal controls: "
           "segregation of duties, maker-checker approval above limits, three-way matching, duplicate checks and strict "
           "control of vendor-master changes {c:32}, codified for audit in frameworks such as COSO {c:32}, {c:coso_genai}, "
           "the Sarbanes-Oxley Act {c:sox}, PCAOB AS 2201 {c:pcaob_2201}, SOC 2 criteria {c:soc2} and the Three Lines "
           "Model {c:three_lines}. Process-mining work on real purchase-to-pay event logs shows how often such processes "
           "deviate from their designed paths {c:bpi2019}, {c:vanderaalst2016}, and forensic accounting has long used "
           "statistical regularities to find manipulated amounts {c:nigrini2012}.")
    R.para("Computer security formalised the same ideas half a century ago. Saltzer and Schroeder's separation of "
           "privilege and least privilege {c:saltzer1975}, Clark and Wilson's commercial integrity model with its "
           "certified transformation procedures and separation of duty {c:clark1987}, Biba's integrity levels "
           "{c:biba1977}, the Chinese Wall policy {c:brewer1989} and role-based access control with separation-of-duty "
           "constraints {c:sandhu1996}, {c:ferraiolo2001}, {c:simon1997}, {c:li2007}, {c:bertino1999} were all designed "
           "for systems in which a single actor must not be able to complete a sensitive transaction alone. NIST SP "
           "800-53 still lists separation of duties and least privilege as baseline controls {c:nist_80053}.")
    R.para("LLM agents are, in an important sense, clerks who can be deceived at machine speed. In indirect prompt "
           "injection, text in data that an application processes is interpreted as instructions {c:33}, {c:2211.09527}, "
           "{c:2306.05499}; a tool-using agent that follows such text becomes a confused deputy {c:hardy1988}. Meta's "
           "Agents Rule of Two {c:9} and Willison's lethal trifecta {c:trifecta} both say that no session should combine "
           "untrusted input, sensitive access and the power to act. A naive accounts-payable agent needs all three.")
    R.para("Defences inside the model have not closed the gap. Instruction hierarchies {c:2404.13208}, {c:2604.09443}, "
           "{c:2505.18907}, structured-query training {c:2402.06363}, preference optimisation {c:2410.05451}, "
           "{c:2507.02735} and detectors {c:41}, {c:2504.11358}, {c:2501.15145} all reduce attack success, yet adaptive "
           "attackers bypassed twelve recent defences in most cases {c:34}, {c:2503.00061}. System-level designs fare "
           "better: CaMeL {c:35} and its successors {c:2505.22852}, {c:2610.05640}, {c:2609.18674}, information-flow "
           "control {c:2505.23643}, {c:2409.19091}, privilege control {c:2504.11703} and design patterns {c:36}, "
           "{c:dual_llm}. This report takes finance's own control vocabulary seriously, implements the deterministic "
           "controls as code that the model cannot override, and measures what an attacker can still extract.")


def section4(R, V):
    R.h1("4. Problem Statement and Research Questions")
    R.para("The task is to let an agent process a realistic accounts-payable workload of purchase orders, receipts, PDF "
           "and structured invoices, supplier e-mails and a weekly payment run, while an adversary who controls only "
           "supplier-facing content tries to divert or inflate payments. For every inbox item the system returns an "
           "action (pay, hold, escalate or reject), a payment where appropriate, and an audit trail of evidence and "
           "control decisions.")
    R.para("The main research question is unchanged: **can classic internal controls, re-expressed as agent architecture "
           "and enforced as code, bound the money that a manipulated LLM agent can divert in procure-to-pay, while "
           "preserving most of the automation value at a fixed analyst review budget?**")
    R.rq("RQ1 (Exposure).", "How much value can invoice- and e-mail-borne attacks divert from undefended and "
         "conventionally defended agents, and how does diverted value differ from attack success rate as a risk measure?")
    R.rq("RQ2 (Controls versus model-level defences).", "Do segregation-of-duties sessions with deterministic "
         "controls-as-code reduce diverted value more than prompt-level, detector-level and capability-based defences, "
         "at matched straight-through processing and review budget?")
    R.rq("RQ3 (Rule of Two in practice).", "Can an accounts-payable workflow be decomposed so that every LLM session "
         "satisfies the Agents Rule of Two while retaining most of the benign straight-through processing rate?")
    R.rq("RQ4 (Channel).", "Does structured e-invoicing (UBL and Peppol PINT AE) shrink the attack surface relative to "
         "PDF-and-e-mail intake, or do its free-text fields preserve it?")
    R.rq("RQ5 (Adaptive attackers).", "Which defences keep their loss reduction when the attacker knows the controls "
         "and searches adaptively, and where does the residual loss concentrate?")
    R.rq("RQ6 (Exploratory).", "Does the OpMech order-gap between consolidating against verified records and expanding "
         "into new evidence flag manipulated documents better than chance, and does it survive adaptive attack?")
    R.rq("RQ7 (Composition, added in the interim phase).", "Does segregating duties between LLM sessions bound loss by "
         "itself, or only when the channel between sessions is certified by deterministic code? We add this question "
         "because the first results made it unavoidable (Section 7.8).")
