"""Agents Rule of Two per session, and the Transitive Rule of Two (TRo2) over a workflow.

Meta's Agents Rule of Two asks that no single session combine [A] untrusted input,
[B] sensitive data or systems and [C] state change or external communication. It is a
per-session test. In multi-agent workflows untrusted content can reach a session
indirectly: through another model's free-text output, a shared note store or memory.
TRo2 propagates untrusted taint along every data-flow edge of the workflow graph and
stops it only at *certified* nodes, i.e. deterministic code that re-derives
integrity-critical fields from verified records (Clark-Wilson transformation
procedures). A workflow satisfies TRo2 when no session whose inputs are tainted also
holds [B] and [C], and no integrity-critical sink is reachable from untrusted content
without passing a certified node.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

CRITICAL_SINKS = {"vendor_master.iban", "payment.beneficiary", "payment.amount"}


@dataclass
class Session:
    name: str
    llm: bool
    B: bool
    C: bool


def workflow(config: str) -> tuple[nx.DiGraph, dict[str, Session]]:
    """Hand-encoded data-flow graphs of the SoD-Bench configurations."""
    g = nx.DiGraph()
    S: dict[str, Session] = {}

    def sess(name, llm, B, C):
        S[name] = Session(name, llm, B, C)
        g.add_node(name, kind="llm" if llm else "code")

    def store(name, certified=False):
        g.add_node(name, kind="store", certified=certified)

    g.add_node("supplier_content", kind="source")
    for s in ("erp_records", "notes", *CRITICAL_SINKS):
        store(s)
    if config in ("D0", "D1", "D2", "D3", "D6c"):
        sess("agent", True, True, True)
        g.add_edges_from([("supplier_content", "agent"), ("erp_records", "agent"), ("notes", "agent"),
                          ("agent", "notes"), ("agent", "payment.beneficiary"), ("agent", "payment.amount")])
        if config != "D3":
            g.add_edge("agent", "vendor_master.iban")
        if config == "D2":
            sess("detector", False, False, False)   # filters but does not certify values
    elif config == "D4":
        sess("p_llm", True, True, True)         # privileged planner never sees untrusted content
        sess("q_llm", True, False, False)       # quarantined extractor
        sess("capability_policy", False, True, False)
        g.add_edges_from([("supplier_content", "q_llm"), ("q_llm", "interpreter_values"),
                          ("interpreter_values", "capability_policy"), ("erp_records", "p_llm"),
                          ("p_llm", "capability_policy"), ("capability_policy", "payment.amount"),
                          ("erp_records", "capability_policy")])
        g.add_node("interpreter_values", kind="store")
        g.nodes["capability_policy"]["certifies"] = {"payment.beneficiary", "vendor_master.iban"}
        g.add_edges_from([("capability_policy", "payment.beneficiary"), ("capability_policy", "vendor_master.iban")])
    elif config in ("D6", "D6a", "D6b"):
        sess("maker", True, True, False)        # read-only lookups, emits typed proposal only
        sess("checker", False, True, True)
        sess("payer", False, True, True)
        g.add_node("proposal", kind="store")
        g.add_edges_from([("supplier_content", "maker"), ("erp_records", "maker"), ("maker", "proposal"),
                          ("proposal", "checker"), ("erp_records", "checker"), ("checker", "payer"),
                          ("payer", "payment.beneficiary"), ("payer", "payment.amount"),
                          ("checker", "vendor_master.iban")])
        certifies = {"payment.amount"}
        if config != "D6a":
            certifies.add("payment.beneficiary")
        if config != "D6b":
            certifies.add("vendor_master.iban")
        g.nodes["checker"]["certifies"] = certifies
    elif config == "D7":
        sess("maker", True, True, False)
        sess("payer_llm", True, True, True)
        g.add_node("summary", kind="store")
        g.add_edges_from([("supplier_content", "maker"), ("erp_records", "maker"), ("maker", "summary"),
                          ("maker", "notes"), ("summary", "payer_llm"), ("notes", "payer_llm"),
                          ("erp_records", "payer_llm"), ("payer_llm", "payment.beneficiary"),
                          ("payer_llm", "payment.amount"), ("payer_llm", "vendor_master.iban")])
    elif config == "D5":
        sess("human", False, True, True)
        g.add_node("human", kind="human", certifies=set(CRITICAL_SINKS))
        g.add_edges_from([("supplier_content", "human"), ("human", "payment.beneficiary"),
                          ("human", "payment.amount"), ("human", "vendor_master.iban")])
    return g, S


def analyse(config: str) -> dict:
    g, S = workflow(config)
    direct_A = {n for n in S if g.has_edge("supplier_content", n)}
    per_session = {}
    for n, s in S.items():
        if not s.llm:
            continue
        props = (n in direct_A) + s.B + s.C
        per_session[n] = props <= 2
    # Per-field taint: a node that certifies field f blocks propagation of f (it re-derives f from
    # verified records); any certifying node emits only typed, validated values, so it also stops
    # free-text taint from reaching downstream sessions.
    tainted_sinks = set()
    for f in CRITICAL_SINKS:
        frontier, seen = ["supplier_content"], {"supplier_content"}
        while frontier:
            u = frontier.pop()
            if f in g.nodes[u].get("certifies", set()):
                continue
            for v in g.successors(u):
                if v == f:
                    tainted_sinks.add(f)
                elif v not in CRITICAL_SINKS and v not in seen:
                    seen.add(v)
                    frontier.append(v)
    tainted_sessions, frontier, seen = set(), ["supplier_content"], {"supplier_content"}
    while frontier:
        u = frontier.pop()
        if g.nodes[u].get("certifies"):
            continue
        for v in g.successors(u):
            if v not in CRITICAL_SINKS and v not in seen:
                seen.add(v)
                frontier.append(v)
                if v in S and S[v].llm:
                    tainted_sessions.add(v)
    tro2_sessions = all(not (S[n].B and S[n].C) for n in tainted_sessions)
    return {"config": config, "rule_of_two_per_session": all(per_session.values()) if per_session else True,
            "sessions": per_session, "tainted_llm_sessions": sorted(tainted_sessions),
            "uncertified_critical_sinks": sorted(tainted_sinks),
            "tro2": tro2_sessions and not tainted_sinks}


def table(configs=("D0", "D1", "D2", "D3", "D4", "D5", "D6", "D6a", "D6b", "D6c", "D7")) -> list[dict]:
    return [analyse(c) for c in configs]
