"""Project charter primitives for kernel-diffguard.

These are deliberately small: they give the young project a tested, importable
surface while the deeper git and kernel-analysis machinery is designed.
"""

from enum import StrEnum


class AnalysisGoal(StrEnum):
    """High-level analysis goals the project exists to support."""

    MALICIOUS_CHANGE_DETECTION = "malicious-change-detection"
    UPDATE_IMPACT_ANALYSIS = "update-impact-analysis"
    PROVENANCE_AND_TREE_INTEGRITY = "provenance-and-tree-integrity"
    MAILING_LIST_CONTEXT = "mailing-list-context"


def default_goals() -> tuple[AnalysisGoal, ...]:
    """Return the initial public charter goals in priority order."""

    return (
        AnalysisGoal.MALICIOUS_CHANGE_DETECTION,
        AnalysisGoal.UPDATE_IMPACT_ANALYSIS,
        AnalysisGoal.PROVENANCE_AND_TREE_INTEGRITY,
        AnalysisGoal.MAILING_LIST_CONTEXT,
    )


def summarize_goals() -> str:
    """Summarize the project purpose for CLI and documentation surfaces."""

    return (
        "Analyze git repositories, starting with the Linux kernel, to detect "
        "malicious or suspicious changes, reason about provenance and tree "
        "integrity, and explain the system impact of updating from commit X "
        "to commit Y with supporting mailing-list context when available."
    )
