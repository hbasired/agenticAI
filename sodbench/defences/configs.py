"""Defence configurations compared under one protocol (proposal Table 7, plus D7).

Each configuration states which tools the agent holds directly and how its intents
are enforced. Model-level defences (D1 spotlighting, D2 detector) change what the
agent sees or believes; system-level defences (D3 tool filtering, D4 capability
policy, D6 controls-as-code) change what the agent is able to do.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from sodbench.controls.policy import PolicyPack


@dataclass
class ConfigSpec:
    name: str
    label: str
    tools: frozenset = frozenset({"pay_any", "update_bank", "onboard", "note"})
    typed: bool = False          # maker emits a typed proposal; deterministic checker decides (CGA)
    spotlight: bool = False      # D1: datamarking + hardened system prompt
    detector: bool = False       # D2: screen all untrusted text with a classifier
    camel: bool = False          # D4: plan-then-execute with capability policy on tool arguments
    human_all: bool = False      # D5: a human approves every payment
    advisory: bool = False       # D6c: controls offered as an optional tool only
    naive_sod: bool = False      # D7: two LLM sessions with a free-text hand-off
    structured_extraction: bool = False  # CGA v0.3: UBL e-invoices parsed by deterministic code, not an LLM
    policy: PolicyPack = field(default_factory=PolicyPack)
    llm_calls_per_item: float = 1.0
    source: str = ""


def all_configs() -> dict[str, ConfigSpec]:
    base = PolicyPack()
    generic = replace(base, vop_enabled=False)   # SOP of a generic agent: no VoP service in its toolset
    c = {
        "D0": ConfigSpec("D0", "Single agent, all tools", policy=generic, source="-"),
        "D1": ConfigSpec("D1", "D0 + spotlighting, hardened prompt", spotlight=True, policy=generic, source="[40]"),
        "D2": ConfigSpec("D2", "D0 + prompt-injection detector", detector=True, policy=generic, source="[41], [44]"),
        "D3": ConfigSpec("D3", "D0 + least-privilege tool filtering", tools=frozenset({"pay_any", "note"}), policy=generic, source="[31]"),
        "D4": ConfigSpec("D4", "Plan-then-execute, quarantined LLM, capability policy", camel=True,
                         tools=frozenset({"pay_any", "note"}), llm_calls_per_item=2.0, policy=generic,
                         source="[35], [36]"),
        "D5": ConfigSpec("D5", "Human approval of every payment", human_all=True, policy=generic, source="-"),
        "D6": ConfigSpec("D6", "CGA: SoD sessions, controls-as-code, provenance", typed=True, tools=frozenset(),
                         policy=base, source="this work"),
        "D6a": ConfigSpec("D6a", "CGA without provenance rule", typed=True, tools=frozenset(),
                          policy=replace(base, provenance_rule=False), source="this work"),
        "D6b": ConfigSpec("D6b", "CGA without call-back protocol", typed=True, tools=frozenset(),
                          policy=replace(base, require_callback=False), source="this work"),
        "D6c": ConfigSpec("D6c", "CGA controls as an optional (advisory) tool", advisory=True, policy=base,
                          source="this work"),
        "D7": ConfigSpec("D7", "Naive SoD: two LLM sessions, free-text hand-off", naive_sod=True,
                         tools=frozenset({"pay_any", "update_bank", "note"}), llm_calls_per_item=2.0,
                         policy=generic, source="this work"),
    }
    return c


INJECTION_SENSITIVE = {"A1", "A2", "A3", "A9"}   # families whose success relies on instructions in content


def cga_versions() -> dict[str, ConfigSpec]:
    """Frozen CGA design versions used in the benchmark campaign (see docs/benchmarks.md)."""
    base = PolicyPack()
    return {
        "v0.1": ConfigSpec("D6-v0.1", "CGA v0.1: global 2 % price tolerance", typed=True, tools=frozenset(),
                           policy=base, source="this work"),
        "v0.2": ConfigSpec("D6-v0.2", "CGA v0.2: pay PO price, route every price variance to the buyer", typed=True,
                           tools=frozenset(), policy=replace(base, price_policy="po_price"), source="this work"),
        "v0.3": ConfigSpec("D6-v0.3", "CGA v0.3: vendor tolerance groups + deterministic UBL extraction", typed=True,
                           tools=frozenset(), policy=replace(base, price_policy="vendor_groups"),
                           structured_extraction=True, source="this work"),
    }

