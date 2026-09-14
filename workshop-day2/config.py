"""Kestrel Goat (Day 2 - the interior) - central configuration.

    Day 1 secured the edge. Today we assume all of it was bypassed.

So this build STARTS where Day 1 ended. Every Day 1 control is already on, and is
marked `locked` below - not because you cannot turn it off, but because turning it
off is not today's lesson. Today's question is different:

    not "how do we keep them out"
    but "given that they're in - how much damage, will we notice, and what did
         we refuse to automate"

The nine Day 2 controls start OFF. Those are the ones you build today.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict

CONTROLS: dict[str, dict] = {
    # ---- Day 1, the edge. Already yours. Locked on. --------------------------------
    "SECURE_INTAKE":            dict(day=1, block=2,  locked=True,  label="Layered intake validation",          tutorial="v02-direct-injection"),
    "SECURE_PROVENANCE":        dict(day=1, block=2,  locked=True,  label="Provenance tagging of retrieval",    tutorial="v03-indirect-injection"),
    "SECURE_TOOLS":             dict(day=1, block=3,  locked=True,  label="Narrow typed tools",                 tutorial="v05-tool-argument-injection"),
    "SECURE_EGRESS":            dict(day=1, block=3,  locked=True,  label="URL allowlist (anti-SSRF)",          tutorial="v07-ssrf-egress"),
    "SECURE_TOOL_RESULTS":      dict(day=1, block=3,  locked=True,  label="Tool-result validation",             tutorial="v06-tool-result-side-door"),
    "SECURE_EXECUTOR":          dict(day=1, block=3,  locked=True,  label="Secure tool executor chokepoint",    tutorial="v05-tool-argument-injection"),
    "SECURE_AUTHZ":             dict(day=1, block=4,  locked=True,  label="Action-time RBAC (3 levels)",        tutorial="v04-authz-at-action-time"),
    "SECURE_TENANCY":           dict(day=1, block=4,  locked=True,  label="Tenancy filter at the data layer",   tutorial="v01-cross-tenant-leak"),
    "SECURE_NO_CREDS_IN_STATE": dict(day=1, block=4,  locked=True,  label="Credentials out of the context",     tutorial="v04-authz-at-action-time"),

    # ---- Day 2, the interior. CONTAIN - DETECT - JUDGE. Build these today. ---------
    "SECURE_STATE_SPLIT":       dict(day=2, block=5,  locked=False, label="Trusted/untrusted state split",      tutorial="v08-state-poisoning"),
    "SECURE_THREAD_IDS":        dict(day=2, block=5,  locked=False, label="Random thread IDs bound to identity",tutorial="v09-thread-id-guessing"),
    "SECURE_MEMORY_WRITES":     dict(day=2, block=5,  locked=False, label="Memory write governance",            tutorial="v10-memory-landmine"),
    "SECURE_QUARANTINE":        dict(day=2, block=6,  locked=False, label="Quarantine node on sub-agents",      tutorial="v11-trust-inheritance"),
    "SECURE_PRIV_SEP":          dict(day=2, block=6,  locked=False, label="Privilege separation reader/actor",  tutorial="v11-trust-inheritance"),
    "SECURE_OUTPUT_GUARD":      dict(day=2, block=7,  locked=False, label="Output guardrails (says + does)",    tutorial="v12-silent-exfiltration"),
    "SECURE_TELEMETRY":         dict(day=2, block=8,  locked=False, label="Behavioural observability",          tutorial="v13-looks-like-normal-traffic"),
    "SECURE_HITL":              dict(day=2, block=9,  locked=False, label="Human interrupt before the action",  tutorial="v14-irreversible-action"),
    "SECURE_LIMITS":            dict(day=2, block=10, locked=False, label="Five rate & cost limits",            tutorial="v15-cost-exhaustion"),
}

DAY1 = [k for k, v in CONTROLS.items() if v["day"] == 1]
DAY2 = [k for k, v in CONTROLS.items() if v["day"] == 2]

PROFILES: dict[str, list[str]] = {
    # How today starts: the edge is secured, the interior is dark.
    "day1-only": DAY1,
    # What Workshop 2 asks you to reach.
    "secure":    DAY1 + DAY2,
    # For the curious: what happens with nothing at all. Day 1 all over again.
    "naked":     [],
}


@dataclass
class Settings:
    llm_provider: str = os.getenv("LLM_PROVIDER", "mock")
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
    model: str = os.getenv("KESTREL_MODEL", "meta-llama/llama-3.1-8b-instruct")
    openrouter_base: str = os.getenv("OPENROUTER_BASE", "https://openrouter.ai/api/v1")
    # llama3.1:8b lands all eight interior attacks. llama3.2:3b is half the
    # download but will not write the memory in b4 - see the README model table.
    ollama_base: str = os.getenv("OLLAMA_BASE", "http://localhost:11434/v1")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

    db_path: str = os.getenv("KESTREL_DB", "data/kestrel.db")
    checkpoint_path: str = os.getenv("KESTREL_CHECKPOINTS", "data/checkpoints.db")
    max_steps: int = int(os.getenv("KESTREL_MAX_STEPS", "12"))

    # Block 10 - five independent levels. One cap is a cap on one thing only.
    #
    # Environment-driven so a hosted demo can be tuned without a redeploy. Note
    # that the levels are checked IN ORDER (steps, loop, tokens, cost), so to
    # demonstrate a particular cap firing, every level above it has to be loose
    # enough to let the run reach it. As shipped the cost ceiling is unreachable
    # on purpose-built numbers: $0.25 needs 125,000 tokens and the session cap
    # stops at 3,000. See DEPLOY.md for the demo values.
    limit_sessions_per_min: int = int(os.getenv("KESTREL_LIMIT_SESSIONS_PER_MIN", "5"))
    limit_steps_per_session: int = int(os.getenv("KESTREL_LIMIT_STEPS_PER_SESSION", "6"))
    limit_repeat_cycle: int = int(os.getenv("KESTREL_LIMIT_REPEAT_CYCLE", "3"))
    limit_tokens_per_session: int = int(os.getenv("KESTREL_LIMIT_TOKENS_PER_SESSION", "3000"))
    limit_tokens_per_day: int = int(os.getenv("KESTREL_LIMIT_TOKENS_PER_DAY", "30000"))
    limit_cost_ceiling_usd: float = float(os.getenv("KESTREL_LIMIT_COST_CEILING_USD", "0.25"))

    # Block 9 - the three-factor test, in a number. Small refund autonomous;
    # large refund interrupted.
    refund_autonomous_ceiling_cents: int = 5_000

    controls: dict[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key, meta in CONTROLS.items():
            default = "1" if meta["locked"] else "0"
            self.controls.setdefault(key, os.getenv(key, default).lower() in ("1", "true", "yes", "on"))

    @property
    def active_model(self) -> str:
        if self.llm_provider == "mock":
            return "mock"
        return self.ollama_model if self.llm_provider == "ollama" else self.model

    def on(self, key: str) -> bool:
        if key not in CONTROLS:
            raise KeyError(f"unknown control {key!r}")
        return self.controls[key]

    def set(self, key: str, value: bool) -> None:
        if key not in CONTROLS:
            raise KeyError(f"unknown control {key!r}")
        self.controls[key] = bool(value)

    def apply_profile(self, name: str) -> None:
        if name not in PROFILES:
            raise KeyError(f"unknown profile {name!r}; try {list(PROFILES)}")
        wanted = set(PROFILES[name])
        for key in CONTROLS:
            self.controls[key] = key in wanted

    def snapshot(self) -> dict:
        d = asdict(self)
        d.pop("openrouter_api_key", None)
        return d


settings = Settings()
