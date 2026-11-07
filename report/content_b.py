"""Interim report content, part B: Section 5 (literature review)."""
from __future__ import annotations


def section5(R, V):
    R.h1("5. Literature Review")
    R.para("The review was extended from 52 to 299 sources for this interim report. All arXiv entries were checked "
           "against the arXiv API in November 2026; standards, books and classic papers are cited from their published "
           "versions. Because agent security moves quickly, recent preprints are flagged as such: many 2026 works cited "
           "here have not yet been peer reviewed, and for several we have read only the abstract, which we state where "
           "it matters.")
    R.h2("5.1 Agentic AI in supply chain and finance")
    R.para("Agentic AI research in operations has moved from capability demonstrations to questions of reliability. In "
           "the MIT Beer Game, LLM agents reduced total supply-chain cost relative to human teams in their best "
           "configuration but showed run-to-run instability {c:25}; related work reproduces classic supply-chain game "
           "results with LLMs {c:26}, and AIM-Bench documents decision biases of agentic inventory managers "
           "{c:2508.11416}. In trade compliance, HSCodeComp reports a wide gap between the best agent and human experts "
           "in tariff classification (source-reported {c:21}, {c:22}). In financial crime, agentic pipelines classify "
           "money-laundering typologies {c:23} and draft suspicious-activity narratives with investigators in the loop "
           "{c:24}; FinRobot packages LLM agents for financial analysis {c:2405.14767}; long-horizon evaluation questions "
           "the apparent edge of LLM trading strategies {c:28}; and adversarial market benchmarks probe their robustness "
           "{c:29}. Enterprise benchmarks extend this to strategic decision-making {c:2609.37658}.")
    R.para("The newest finance-agent work turns from accuracy to accountability. NumTrace audits where the numbers in "
           "financial analysts' agent outputs come from {c:2610.34887}; work on auditable agents {c:2604.05485} and on "
           "verifiable agent insurance {c:2610.18230} treats agent behaviour as something to be evidenced and priced. "
           "These are close in spirit to our use of money as the unit of risk, but none of them, as far as we can tell "
           "from the papers we read, models a procure-to-pay process with orders, receipts and internal controls.")
    R.h2("5.2 Prompt injection and agent-security benchmarks")
    R.para("Indirect prompt injection was characterised against real LLM-integrated applications by Greshake et al. "
           "{c:33}, building on direct injection {c:2211.09527} and application-level attacks {c:2306.05499}; games and "
           "competitions collected large attack corpora {c:2311.01011}, {c:2311.16119}, {c:2406.07954}; optimisation-"
           "based attacks transfer across aligned models {c:2307.15043}; and Liu et al. formalised attacks and defences "
           "{c:30}. Agent benchmarks followed: InjecAgent {c:37}, Agent Security Bench {c:38}, AgentDojo with state-"
           "checked utility and security {c:31}, BIPIA {c:2312.14197}, WASP for web agents {c:2504.18575}, AgentHarm "
           "{c:2410.09024}, Agent-SafetyBench {c:2412.14470}, R-Judge {c:2401.10019}, ToolEmu's emulated sandbox "
           "{c:2309.15817}, τ-bench and τ²-bench for policy-following tool use {c:39}, {c:2506.07982}, multi-turn "
           "adaptive adversaries {c:2607.18063} and phishing-specific evaluation of e-mail agents {c:2610.31404}. "
           "Finance arrived in 2026 with FinVault {c:6}, FraudBench {c:7}, an agentic-commerce systematisation {c:27} "
           "and a payment-authorisation benchmark replaying a public capture-the-flag event {c:2609.22076}.")
    R.para("The benchmark-methodology literature shapes how SoD-Bench reports results. Checklists and audits of agentic "
           "benchmarks warn about invalid tasks, leaked answers and judge errors {c:2507.02825}, {c:2607.02577}, "
           "{c:2411.12990}; cost-aware and multi-dimensional evaluation is recommended {c:2407.01502}, {c:2511.14136}, "
           "{c:2608.00805}; and recent work argues that benchmarks should be maintained like software {c:2611.08417}. We "
           "follow these by computing every outcome from environment state, separating development from held-out "
           "templates, reporting cost, and versioning the benchmark with its code.")
    R.table(["Work", "Setting", "What it measures", "Gap for procure-to-pay"],
            [["AgentDojo {c:31}", "Workspace, Slack, travel, e-banking", "Utility and attack success from state",
              "No orders, receipts or internal controls; no loss metric"],
             ["InjecAgent {c:37}; ASB {c:38}", "Tool calls across many scenarios", "Attack success by technique and stage",
              "Not workflow-grounded; no control semantics"],
             ["FinVault {c:6}", "31 regulatory scenarios", "Attack success, false positives",
              "No corporate accounts payable; success rate ignores severity"],
             ["FraudBench {c:7}", "Banking agent vs adaptive caller", "Attack security", "Customer dialogue, not supplier documents"],
             ["APort Vault {c:2609.22076}", "Payment agent, replayed CTF attacks", "Five events per evaluation",
              "Single payment tool; no three-way match or vendor master"],
             ["CrackedPDFs {c:2607.19396}", "Hidden injection in PDFs", "Detector accuracy", "Detection only; no downstream money"],
             ["SoD-Bench (this work)", "Corporate P2P: PDF and UBL invoices, e-mail, payment runs",
              "Diverted value, Loss@B, STP, false holds, adaptive residual", "—"]],
            [1700, 2300, 2500, 2860], "Closest benchmarks and what SoD-Bench adds. Descriptions summarise the cited papers.")
    R.h2("5.3 Defences: model-level versus system-level")
    R.para("Model-level defences change what the model believes or sees. Prompt-level defences mark untrusted text "
           "{c:40}; training-time defences teach models to rank instructions by privilege {c:2404.13208}, {c:2604.09443}, "
           "{c:2505.18907} or to ignore data-borne instructions {c:2402.06363}, {c:2410.05451}, {c:2507.02735}; detectors "
           "screen inputs {c:41}, {c:44}, {c:2504.11358}, {c:2501.15145}, {c:2604.12284}, {c:2607.22545} or internal "
           "states {c:2411.00348}, {c:2406.00799}; and inference-time checks compare runs or align actions with tasks "
           "{c:42}, {c:52}, {c:2412.16682}, {c:2507.15219}. Guardrail agents and step-level guards add policy reasoning "
           "around tool calls {c:2406.09187}, {c:2503.22738}, {c:2601.10156}, {c:2502.11448}. Google DeepMind's account "
           "of defending Gemini shows how much engineering such layers need {c:2505.14534}. All are probabilistic, and "
           "adaptive attackers have broken representatives of each {c:34}, {c:2503.00061}; automated red-teaming engines "
           "make such adaptation cheap {c:2503.15754}, {c:2610.08951}, {c:2606.23927}.")
    R.para("System-level defences change what an agent can do. The dual-LLM pattern {c:dual_llm} and CaMeL {c:35} keep "
           "untrusted data out of control flow and enforce capability policies; follow-up work operationalises CaMeL for "
           "enterprises {c:2505.22852}, adds temporal-logic verification {c:2609.18674}, and asks whether its guarantees "
           "compose in multi-agent hierarchies {c:2610.05640}. Information-flow control systems label data and block "
           "policy-violating flows {c:2505.23643}, {c:2409.19091}, {c:2503.15547}, {c:2502.08966}; isolation architectures "
           "separate applications {c:2403.04960}, {c:2504.20984}; privilege-control and fine-grained authorisation "
           "systems restrict tools {c:2504.11703}, {c:2609.37196}; contextual policies are generated per task "
           "{c:2501.17070}; rule-based isolation and plan-then-execute designs are catalogued with implementation advice "
           "{c:36}, {c:2506.12104}, {c:2509.08646}. CGA belongs to this family. Its difference is that the policy is "
           "not generic: it is the internal-control system of an accounts-payable function, written as code.")
    R.h2("5.4 Internal controls and payment fraud")
    R.para("COSO's Internal Control-Integrated Framework is the reference model for internal control, and authorisation, "
           "segregation of duties and reconciliation are its operational core {c:32}; COSO's 2026 guidance applies its "
           "principles to generative AI {c:coso_genai}, and audit standards and attestation criteria make the controls "
           "testable {c:sox}, {c:pcaob_2201}, {c:soc2}. Fraud data explains the controls: billing schemes are among the "
           "most common occupational frauds {c:15}, business email compromise is among the costliest reported crimes "
           "{c:2}, high-precision BEC detection needs sender-specific models {c:cidon2019}, {c:2509.00005}, and look-alike "
           "domains rely on typosquatting and homographs {c:szurdi2014}, {c:gabrilovich2002}. Regulators are shifting "
           "losses: the UK's reimbursement requirement for authorised push payment scams {c:psr_app} and euro-area "
           "Verification of Payee {c:18} both change who pays when a beneficiary is wrong.")
    R.para("E-invoicing changes what an invoice can contain. EN 16931 defines the semantic model {c:en16931}, UBL 2.1 the "
           "syntax {c:ubl21}, Peppol BIS Billing 3.0 the profile {c:43}, and PINT AE the UAE specialisation {c:pint_ae}, "
           "{c:19}; IBANs follow ISO 13616 {c:iso13616}. Invoice-extraction research shows that general-purpose LLMs read "
           "invoices well but not perfectly {c:2604.25927}, {c:2511.05547}, that synthetic invoices can be generated "
           "realistically {c:2508.03754}, and, closest to our straight-through-processing metric, that auto-approval of "
           "extracted fields needs calibrated confidence with bounded residual error {c:2609.20110}. Synthetic data is "
           "standard where real financial data cannot be shared {c:8}, {c:2506.13989}, {c:2509.18499}. This literature "
           "does not yet ask what happens when the clerk being controlled is an LLM.")
    R.h2("5.5 Adaptive evidence handling and the OpMech idea")
    R.para("Consolidation-Expansion Operator Mechanics proposes that adaptive learners alternate between consolidating "
           "what they know and expanding into new evidence, and defines an order-gap measuring how far the two operations "
           "fail to commute {c:12}. A document that tries to override verified records should, intuitively, not commute "
           "with consolidation. The LLM literature gives reasons to expect order effects at all: models use long contexts "
           "unevenly {c:2307.03172}, show position biases across tasks {c:2610.22807}, and order sensitivity has been "
           "exploited as an attack surface {c:2607.24869}. Dual-run and self-consistency methods compare outputs across "
           "runs {c:42}, {c:2203.11171}, {c:2509.19489}. We test the order-gap as an exploratory diagnostic only "
           "(Section 8.6), consistent with how the framework itself is framed {c:12}.")
    R.h2("5.6 Segregation of duties, integrity models and information flow")
    R.para("The theory behind CGA predates LLMs by decades. Saltzer and Schroeder's design principles include separation "
           "of privilege and least privilege {c:saltzer1975}. Clark and Wilson's integrity model, written for commercial "
           "accounting systems, distinguishes constrained data items, which only certified transformation procedures may "
           "change, from unconstrained data items, which must be validated before they affect constrained state, and it "
           "requires separation of duty between those who certify and those who execute {c:clark1987}. Biba's integrity "
           "levels {c:biba1977}, the Chinese Wall policy {c:brewer1989}, role-based access control and its separation-of-"
           "duty constraints {c:sandhu1996}, {c:ferraiolo2001}, {c:simon1997}, {c:li2007} and workflow authorisation "
           "constraints {c:bertino1999} refine these ideas, and capability systems make authority explicit "
           "{c:dennis1966}, {c:miller2006}.")
    R.para("Information-flow security supplies the mechanism. Denning's lattice model {c:denning1976}, Goguen and "
           "Meseguer's noninterference {c:goguen1982} and language-based enforcement {c:sabelfeld2003} define when data "
           "of one integrity level may influence another; dynamic taint tracking implements this at run time "
           "{c:newsome2005}, {c:enck2010}. For LLM agents, recent work redefines information-flow tracking for model-"
           "mediated flows {c:2604.23374}, plans first and controls flows across persistent queries {c:2608.27234}, "
           "brings IFC to browser agents {c:2610.24277}, finds bidirectional data-flow risks in MCP ecosystems "
           "{c:2605.07836}, guarantees confidentiality deterministically {c:2604.19657} and evaluates containment after "
           "exposure {c:2607.23999}. Our provenance rule is the integrity counterpart: a value that originated in "
           "supplier text may enter the payment path only after certified code has re-derived it from verified records.")
    R.h2("5.7 Governed execution, runtime enforcement and agent authorisation")
    R.para("In 2026 several groups converged on the idea that authority must be governed outside the model. Jing studies "
           "separation of duties for privileged operating-system agents with a planner, policy gate, executor and auditor "
           "{c:2609.38224}; the Organizational Control Layer intercepts generated actions before execution and checks them "
           "against role, policy and economic constraints {c:2606.04306}; persona-execution separation {c:2608.27427} and "
           "twin-agent privilege separation {c:2607.19595} split agents into trust domains. Runtime-enforcement systems "
           "check company policy adherence {c:2507.16459}, behavioural specifications {c:2606.26524}, natural-language "
           "policies compiled into predicate programs {c:2610.31062} and domain-specific rules {c:2503.18666}; authorisation "
           "languages such as Cedar are designed to be analysable {c:2403.04651}; formal verification is beginning to reach "
           "agentic systems {c:2608.03609}, {c:2606.04903}; and the cost of verification has itself been measured "
           "{c:2603.19328}. We see CGA as an instance of this movement, specialised to a process whose controls are "
           "already standardised and audited.")
    R.para("Identity and authorisation for agents are being standardised in parallel: authenticated delegation "
           "{c:2501.09674}, agent IDs and visibility {c:2406.12137}, {c:2401.13138}, OpenID Connect and JWT extensions "
           "{c:2509.25974}, {c:2509.13597}, compositional and capability-based delegation {c:2606.03518}, {c:2609.06500}, "
           "least-privilege enforcement for agent skills {c:2605.05868} and attack-surface modelling of agentic platforms "
           "{c:2605.10763}. Verifiable execution histories, process evidence and attestation of actions rather than "
           "agents {c:2602.20214}, {c:2610.40071}, {c:2606.26298} complement the tamper-evident logs we use "
           "{c:haber1991}, {c:crosby2009}, {c:rfc6962}. Governance frameworks frame the obligations: the EU AI Act "
           "{c:eu_ai_act}, the NIST AI RMF and its generative-AI profile {c:nist_rmf}, {c:nist_600_1}, NIST's adversarial "
           "ML taxonomy {c:nist_aml}, ISO/IEC 42001 {c:iso42001}, OWASP's LLM and agentic top-ten lists {c:owasp_llm}, "
           "{c:17}, MITRE ATLAS {c:atlas}, legal analysis of agent governance {c:2501.07913}, NIST's agent standards "
           "work {c:nist_caisi}, {c:nist_identity} and the 2025 International AI Safety Report {c:2501.17805}.")
    R.h2("5.8 Memory, multi-agent and protocol attacks")
    R.para("Attack family A9 in SoD-Bench, cross-agent trust contamination, is an instance of a fast-growing literature. "
           "Memory and knowledge-base poisoning was shown early {c:2407.12784}; 2026 studies systematise memory write "
           "channels {c:2606.04329}, show instructions that persist across sessions {c:2609.13889} and analyse poisoning "
           "in multi-agent systems {c:2603.20357}. Multi-agent systems can be steered to execute arbitrary code "
           "{c:2503.12188}, infections spread between agents {c:2410.07283}, communication itself can be attacked "
           "{c:2502.14847}, and surveys map the risks of interacting agents {c:2502.14143}, {c:2505.02077}, {c:2510.06445}.")
    R.para("Protocols widen the surface. The Model Context Protocol {c:mcp} has a landscape study {c:2503.23278}, tool-"
           "poisoning disclosures {c:invariant}, two security benchmarks {c:2508.13220}, {c:2510.15994}, a hardened "
           "variant {c:2602.01129} and network-level defences against supply-chain injection {c:2604.04426}. Agent2Agent "
           "{c:a2a} has security guidance {c:2504.16902}, a systematic attack analysis {c:2609.10871}, tamper-evident "
           "runtime evidence {c:2609.33924}, comparative threat modelling across protocols {c:2602.11327} and lessons "
           "from internet-protocol history {c:2610.26624}. Agent payment protocols {c:ap2}, {c:acp}, {c:visa_tap} carry "
           "the problem into money: cryptographically valid mandates do not constrain the decisions that produced them "
           "{c:2609.11757}, and behaviour-aware fraud detection is proposed for agent payments {c:2610.27483}, "
           "{c:2604.11430}.")
    R.h2("5.9 Measurement: structured outputs, calibration and risk")
    R.para("CGA's maker emits typed proposals under constrained decoding. Grammar- and schema-constrained generation is "
           "well developed {c:2307.09702}, {c:2411.15100}, {c:2608.03065} and benchmarked {c:2501.10868}, and structured-"
           "output reliability can be scored {c:2512.23712}. Two recent papers warn that structure is not safety: prefix-"
           "tree interfaces can aid jailbreaks {c:2502.13527} and structured-output backdoors can be implanted in coding "
           "agents {c:2611.00138}. The typed channel in CGA is safe only because the checker re-derives what matters.")
    R.para("Risk scores must be calibrated to be useful for triage. We use expected calibration error {c:naeini2015}, "
           "{c:1706.04599}, aware that LLM confidence is often miscalibrated {c:2605.23909}, and split conformal "
           "prediction {c:vovk2005}, {c:2107.07511} with conformal risk control {c:2208.02814}, which 2026 work applies "
           "to LLM tool calls {c:2607.24343} and compositional agent risk {c:2610.05563}. Loss is summarised with value-"
           "at-risk and conditional value-at-risk {c:jorion2006}, {c:cvar}, coherent risk measures {c:artzner1999} and "
           "the FAIR approach to information risk {c:fair}; uncertainty uses the bootstrap {c:bootstrap}, Wilson intervals "
           "{c:wilson1927} and exact McNemar tests {c:mcnemar}. Datasets and models are documented with datasheets "
           "{c:datasheets}, Croissant metadata {c:croissant} and model cards {c:1810.03993}.")
