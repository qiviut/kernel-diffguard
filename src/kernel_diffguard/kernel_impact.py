"""Linux-kernel path impact hints.

These hints are deterministic review aids. They map touched paths to broad kernel
areas and retest prompts without claiming semantic impact or maliciousness.
"""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]


def kernel_impacts_for_paths(paths: list[str]) -> list[JsonObject]:
    """Return stable path-heuristic kernel impact hints for touched paths."""

    impacts = [_impact_for_rule(rule, paths) for rule in _RULES]
    return [impact for impact in impacts if impact is not None]


def _impact_for_rule(rule: JsonObject, paths: list[str]) -> JsonObject | None:
    evidence = [f"path:{path}" for path in sorted(paths) if _matches(rule, path)]
    if not evidence:
        return None
    return {
        "id": rule["id"],
        "summary": rule["summary"],
        "evidence": evidence,
        "retest_hints": rule["retest_hints"],
        "uncertainty": "path-heuristic",
    }


def _matches(rule: JsonObject, path: str) -> bool:
    lowered = path.lower()
    return any(lowered == exact for exact in rule.get("exact", ())) or any(
        lowered.startswith(prefix) for prefix in rule.get("prefixes", ())
    )


_RULES: tuple[JsonObject, ...] = (
    {
        "id": "kconfig",
        "summary": "Kernel configuration surface changed.",
        "exact": ("kconfig",),
        "prefixes": ("kconfig.",),
        "retest_hints": ["affected Kconfig option coverage", "defconfig/build matrix checks"],
    },
    {
        "id": "drivers",
        "summary": "Driver code changed.",
        "prefixes": ("drivers/",),
        "retest_hints": [
            "affected hardware or emulated driver tests",
            "module load/unload smoke tests",
        ],
    },
    {
        "id": "architecture",
        "summary": "Architecture-specific kernel code changed.",
        "prefixes": ("arch/",),
        "retest_hints": [
            "affected architecture boot smoke tests",
            "toolchain-specific build checks",
        ],
    },
    {
        "id": "syscall",
        "summary": "System-call or user/kernel ABI surface may have changed.",
        "prefixes": ("kernel/sys", "include/uapi/", "tools/testing/selftests/"),
        "retest_hints": ["ABI compatibility checks", "relevant selftests"],
    },
    {
        "id": "filesystem",
        "summary": "Filesystem code changed.",
        "prefixes": ("fs/",),
        "retest_hints": ["mount/read-write smoke tests", "filesystem-specific regression tests"],
    },
    {
        "id": "networking",
        "summary": "Networking stack or network driver code changed.",
        "prefixes": ("net/", "drivers/net/"),
        "retest_hints": ["network protocol smoke tests", "affected driver or socket tests"],
    },
    {
        "id": "scheduler",
        "summary": "Scheduler code changed.",
        "prefixes": ("kernel/sched/", "kernel/scheduler"),
        "retest_hints": ["scheduler selftests", "latency and workload smoke tests"],
    },
    {
        "id": "memory-management",
        "summary": "Memory-management code changed.",
        "prefixes": ("mm/",),
        "retest_hints": ["memory-management selftests", "stress and reclaim smoke tests"],
    },
    {
        "id": "security-sensitive",
        "summary": "Security-sensitive kernel surface changed.",
        "prefixes": ("security/", "crypto/", "certs/", "kernel/bpf/"),
        "retest_hints": [
            "security subsystem regression tests",
            "policy and permission smoke tests",
        ],
    },
)
