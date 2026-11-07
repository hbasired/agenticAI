"""Bibliography for the interim report.

References [1]-[52] are the proposal's, unchanged and in the same order. New references
start at [53]. arXiv entries are formatted from metadata verified through the arXiv API
(references/arxiv_meta.json); venues are stated only where the arXiv record confirms them.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
META = json.load(open(os.path.join(HERE, "arxiv_meta.json"), encoding="utf8"))

VENUE = {
    "2402.06363": "in Proc. 34th USENIX Security Symposium, 2025", "2410.05451": "in Proc. ACM CCS, 2025",
    "2403.04960": "in Proc. NDSS Symposium, 2025", "2504.20984": "in Proc. NDSS Symposium, 2026",
    "2501.17070": "in Proc. Workshop on Hot Topics in Operating Systems (HotOS), 2025",
    "2506.12104": "in Advances in Neural Information Processing Systems (NeurIPS), 2025",
    "2503.00061": "in Findings of NAACL, 2025", "2406.09187": "in Proc. ICML, 2025",
    "2503.18666": "in Proc. 48th IEEE/ACM International Conference on Software Engineering (ICSE), 2026, pp. 2938-2950",
    "2406.00799": "in Proc. IEEE Conference on Secure and Trustworthy Machine Learning (SaTML), 2025",
    "2211.09527": "in NeurIPS ML Safety Workshop, 2022", "2410.09024": "in Proc. ICLR, 2025",
    "2401.10019": "in Findings of EMNLP, 2024", "2312.14197": "in Proc. ACM KDD, 2025", "2502.14847": "in Proc. ACL, 2025",
    "2401.13138": "in Proc. ACM FAccT, 2024", "2406.12137": "in NeurIPS RegML Workshop, 2024",
    "2501.07913": "Notre Dame Law Review, vol. 101, forthcoming", "2503.14499": "in Advances in Neural Information Processing Systems (NeurIPS), 2025",
    "1706.04599": "in Proc. ICML, 2017", "2510.06445": "Transactions on Machine Learning Research, 2026",
    "2208.02814": "in Proc. ICLR, 2024", "2403.04651": "in Proc. ACM OOPSLA, 2024",
}

NEW_ARXIV = [
    # closest 2026 prior work and adjacent payment / agent-security work
    "2609.38224", "2606.04306", "2609.22076", "2609.11757", "2604.11430", "2608.27427", "2607.19595", "2604.19657",
    "2608.27234", "2610.31404", "2610.27483", "2607.18063", "2610.24277",
    # defences
    "2404.13208", "2402.06363", "2410.05451", "2507.02735", "2505.23643", "2504.11703", "2403.04960", "2409.19091",
    "2503.15547", "2504.20984", "2502.08966", "2501.17070", "2412.16682", "2506.12104", "2504.11358", "2507.15219",
    "2503.00061", "2505.14534", "2505.22852", "2503.22738", "2406.09187", "2503.18666", "2411.00348", "2406.00799",
    "2403.04651",
    # attacks and benchmarks
    "2307.15043", "2211.09527", "2306.05499", "2311.01011", "2311.16119", "2504.18575", "2410.09024", "2506.07982",
    "2309.15817", "2401.10019", "2412.14470", "2406.07954", "2312.14197", "2407.12784",
    # multi-agent systems, protocols, identity, governance, capability trends
    "2503.12188", "2410.07283", "2502.14143", "2505.02077", "2502.14847", "2503.23278", "2501.09674", "2401.13138",
    "2406.12137", "2501.07913", "2503.14499", "2407.01502", "2507.02825", "2501.17805", "2510.06445",
    # statistics, calibration, finance agents
    "2208.02814", "1706.04599", "2405.14767",
]

NON_ARXIV = [
    ("saltzer1975", 'J. H. Saltzer and M. D. Schroeder, "The protection of information in computer systems," Proc. IEEE, vol. 63, no. 9, pp. 1278-1308, 1975.'),
    ("clark1987", 'D. D. Clark and D. R. Wilson, "A comparison of commercial and military computer security policies," in Proc. IEEE Symposium on Security and Privacy, 1987, pp. 184-194.'),
    ("biba1977", 'K. J. Biba, "Integrity considerations for secure computer systems," MITRE Corp., Tech. Rep. MTR-3153, 1977.'),
    ("brewer1989", 'D. F. C. Brewer and M. J. Nash, "The Chinese Wall security policy," in Proc. IEEE Symposium on Security and Privacy, 1989, pp. 206-214.'),
    ("denning1976", 'D. E. Denning, "A lattice model of secure information flow," Communications of the ACM, vol. 19, no. 5, pp. 236-243, 1976.'),
    ("goguen1982", 'J. A. Goguen and J. Meseguer, "Security policies and security models," in Proc. IEEE Symposium on Security and Privacy, 1982, pp. 11-20.'),
    ("sabelfeld2003", 'A. Sabelfeld and A. C. Myers, "Language-based information-flow security," IEEE Journal on Selected Areas in Communications, vol. 21, no. 1, pp. 5-19, 2003.'),
    ("hardy1988", 'N. Hardy, "The confused deputy (or why capabilities might have been invented)," ACM SIGOPS Operating Systems Review, vol. 22, no. 4, pp. 36-38, 1988.'),
    ("sandhu1996", 'R. S. Sandhu, E. J. Coyne, H. L. Feinstein, and C. E. Youman, "Role-based access control models," IEEE Computer, vol. 29, no. 2, pp. 38-47, 1996.'),
    ("ferraiolo2001", 'D. F. Ferraiolo, R. Sandhu, S. Gavrila, D. R. Kuhn, and R. Chandramouli, "Proposed NIST standard for role-based access control," ACM Transactions on Information and System Security, vol. 4, no. 3, pp. 224-274, 2001.'),
    ("simon1997", 'R. T. Simon and M. E. Zurko, "Separation of duty in role-based environments," in Proc. 10th IEEE Computer Security Foundations Workshop, 1997, pp. 183-194.'),
    ("li2007", 'N. Li, M. V. Tripunitara, and Z. Bizri, "On mutually exclusive roles and separation-of-duty," ACM Transactions on Information and System Security, vol. 10, no. 2, 2007.'),
    ("bertino1999", 'E. Bertino, E. Ferrari, and V. Atluri, "The specification and enforcement of authorization constraints in workflow management systems," ACM Transactions on Information and System Security, vol. 2, no. 1, pp. 65-104, 1999.'),
    ("z3", 'L. de Moura and N. Bjørner, "Z3: An efficient SMT solver," in Proc. TACAS, LNCS vol. 4963, 2008, pp. 337-340.'),
    ("hypothesis", 'D. R. MacIver, Z. Hatfield-Dodds et al., "Hypothesis: A new approach to property-based testing," Journal of Open Source Software, vol. 4, no. 43, p. 1891, 2019.'),
    ("coso_genai", 'Committee of Sponsoring Organizations of the Treadway Commission (COSO), "Achieving effective internal control over generative AI (GenAI)," Feb. 2026. [Online]. Available: https://www.coso.org'),
    ("nist_caisi", 'National Institute of Standards and Technology, Center for AI Standards and Innovation, "AI Agent Standards Initiative," Feb. 17, 2026, and "Request for information regarding security considerations for artificial intelligence agents," Federal Register, vol. 91, no. 5, Jan. 8, 2026, Docket NIST-2025-0035.'),
    ("nist_identity", 'National Institute of Standards and Technology, "Design tenets for agent identity management systems," Cybersecurity Insights blog, 2026. [Online]. Available: https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems'),
    ("eu_ai_act", 'European Parliament and Council of the European Union, "Regulation (EU) 2024/1689 laying down harmonised rules on artificial intelligence (Artificial Intelligence Act)," Official Journal of the European Union, Jul. 12, 2024.'),
    ("nist_rmf", 'National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," NIST AI 100-1, Jan. 2023.'),
    ("nist_600_1", 'National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile," NIST AI 600-1, Jul. 2024.'),
    ("nist_aml", 'A. Vassilev, A. Oprea, A. Fordyce, H. Anderson, X. Davies, and M. Hamin, "Adversarial machine learning: A taxonomy and terminology of attacks and mitigations," NIST AI 100-2e2025, Mar. 2025.'),
    ("iso42001", 'ISO/IEC 42001:2023, "Information technology - Artificial intelligence - Management system," International Organization for Standardization, 2023.'),
    ("nist_80053", 'National Institute of Standards and Technology, "Security and privacy controls for information systems and organizations," NIST SP 800-53 Rev. 5, Sep. 2020 (controls AC-5 Separation of Duties and AC-6 Least Privilege).'),
    ("pcaob_2201", 'Public Company Accounting Oversight Board, "AS 2201: An audit of internal control over financial reporting that is integrated with an audit of financial statements."'),
    ("sox", 'Sarbanes-Oxley Act of 2002, Pub. L. No. 107-204, 116 Stat. 745, Section 404.'),
    ("owasp_llm", 'OWASP Foundation, "OWASP Top 10 for LLM Applications 2025," Nov. 2024 (LLM01 Prompt Injection; LLM06 Excessive Agency).'),
    ("atlas", 'MITRE, "ATLAS: Adversarial Threat Landscape for Artificial-Intelligence Systems." [Online]. Available: https://atlas.mitre.org'),
    ("psr_app", 'Payment Systems Regulator, "Authorised push payment (APP) scams reimbursement requirement," in force Oct. 7, 2024.'),
    ("vida", 'Council of the European Union, "Council Directive (EU) 2025/516 of 11 March 2025 amending Directive 2006/112/EC as regards VAT rules for the digital age," 2025.'),
    ("en16931", 'European Committee for Standardization, "EN 16931-1:2017 Electronic invoicing - Part 1: Semantic data model of the core elements of an electronic invoice," 2017.'),
    ("ubl21", 'OASIS, "Universal Business Language Version 2.1," 2013; published as ISO/IEC 19845:2015.'),
    ("pint_ae", 'OpenPeppol, "PINT AE: United Arab Emirates electronic document specifications, version 1.0.3," 2026. [Online]. Available: https://docs.peppol.eu/poac/ae/v1.0.3/'),
    ("iso13616", 'ISO 13616-1:2020, "Financial services - International bank account number (IBAN) - Part 1: Structure of the IBAN," 2020.'),
    ("ap2", 'Google Cloud, "Announcing Agent Payments Protocol (AP2)," Sep. 16, 2025. [Online]. Available: https://cloud.google.com/blog'),
    ("acp", 'OpenAI and Stripe, "Agentic Commerce Protocol," Sep. 29, 2025. [Online]. Available: https://www.agenticcommerce.dev'),
    ("visa_tap", 'Visa, "Trusted Agent Protocol," Oct. 14, 2025. [Online]. Available: https://usa.visa.com'),
    ("mcp", 'Anthropic, "Introducing the Model Context Protocol," Nov. 25, 2024. [Online]. Available: https://www.anthropic.com/news/model-context-protocol'),
    ("a2a", 'Google, "Announcing the Agent2Agent Protocol (A2A)," Apr. 9, 2025. [Online]. Available: https://developers.googleblog.com'),
    ("invariant", 'Invariant Labs, "MCP security notification: Tool poisoning attacks," Apr. 2025. [Online]. Available: https://invariantlabs.ai/blog'),
    ("trifecta", 'S. Willison, "The lethal trifecta for AI agents: private data, untrusted content, and external communication," Jun. 16, 2025. [Online]. Available: https://simonwillison.net'),
    ("dual_llm", 'S. Willison, "The Dual LLM pattern for building AI assistants that can resist prompt injection," Apr. 25, 2023. [Online]. Available: https://simonwillison.net'),
    ("datasheets", 'T. Gebru, J. Morgenstern, B. Vecchione, J. W. Vaughan, H. Wallach, H. Daumé III, and K. Crawford, "Datasheets for datasets," Communications of the ACM, vol. 64, no. 12, pp. 86-92, 2021.'),
    ("croissant", 'M. Akhtar et al., "Croissant: A metadata format for ML-ready datasets," in Advances in Neural Information Processing Systems 37 (Datasets and Benchmarks Track), 2024.'),
    ("cvar", 'R. T. Rockafellar and S. Uryasev, "Optimization of conditional value-at-risk," Journal of Risk, vol. 2, no. 3, pp. 21-41, 2000.'),
    ("bootstrap", 'B. Efron and R. J. Tibshirani, An Introduction to the Bootstrap. New York: Chapman & Hall, 1993.'),
    ("mcnemar", 'Q. McNemar, "Note on the sampling error of the difference between correlated proportions or percentages," Psychometrika, vol. 12, no. 2, pp. 153-157, 1947.'),
    ("protectai", 'ProtectAI, "deberta-v3-base-prompt-injection-v2," model card, Hugging Face, 2024. [Online]. Available: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2'),
    ("fair", 'J. Freund and J. Jones, Measuring and Managing Information Risk: A FAIR Approach. Oxford: Butterworth-Heinemann, 2014.'),
    ("soc2", 'American Institute of Certified Public Accountants, "2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (with revised points of focus, 2022)."'),
    ("three_lines", 'The Institute of Internal Auditors, "The IIA\'s Three Lines Model: An update of the Three Lines of Defense," Jul. 2020.'),
    ("llamacpp_py", 'A. Betlen et al., "llama-cpp-python: Python bindings for llama.cpp," version 0.3.36, PyPI, Oct. 2026.'),
]


def _authors(names: list[str], limit: int = 6) -> str:
    def short(n: str) -> str:
        parts = n.replace(",", "").split()
        if len(parts) == 1:
            return parts[0]
        return " ".join(p[0] + "." for p in parts[:-1]) + " " + parts[-1]
    names = [short(n) for n in names]
    if len(names) > limit:
        return ", ".join(names[:limit]) + " et al."
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + ", and " + names[-1]


def arxiv_entry(aid: str) -> str:
    m = META[aid]
    title = m["title"].replace("$τ$", "τ").replace("$τ^2$", "τ²").rstrip(".")
    year = m["published"][:4]
    venue = VENUE.get(aid)
    base = f'{_authors(m["authors"])}, "{title}," '
    if venue:
        return base + f"{venue}; arXiv:{aid}."
    return base + f"arXiv:{aid}, {year}."


def new_references() -> list[tuple[str, str]]:
    """(key, formatted text) for references [53] onward, in citation order."""
    out = [(aid, arxiv_entry(aid)) for aid in NEW_ARXIV]
    out += NON_ARXIV
    return out


if __name__ == "__main__":
    refs = new_references()
    for i, (k, t) in enumerate(refs, start=53):
        print(f"[{i}] {t}")
    print(f"\n{52 + len(refs)} references in total ({len(refs)} new)")
