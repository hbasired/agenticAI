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
    policy: PolicyPack = field(default_factory=PolicyPack)
    llm_calls_per_item: float = 1.0
    source: str = ""


def all_configs() -> dict[str, ConfigSpec]:
    base = PolicyPack()
    c = {
        "D0": ConfigSpec("D0", "Single agent, all tools", source="-"),
        "D1": ConfigSpec("D1", "D0 + spotlighting, hardened prompt", spotlight=True, source="[40]"),
        "D2": ConfigSpec("D2", "D0 + prompt-injection detector", detector=True, source="[41], [44]"),
        "D3": ConfigSpec("D3", "D0 + least-privilege tool filtering", tools=frozenset({"pay_any", "note"}), source="[31]"),
        "D4": ConfigSpec("D4", "Plan-then-execute, quarantined LLM, capability policy", camel=True,
                         tools=frozenset({"pay_any", "note"}), llm_calls_per_item=2.0, source="[35], [36]"),
        "D5": ConfigSpec("D5", "Human approval of every payment", human_all=True, source="-"),
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
                         source="this work"),
    }
    return c


INJECTION_SENSITIVE = {"A1", "A2", "A3", "A9"}   # families whose success relies on instructions in content
