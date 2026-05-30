"""
Shared triage-zone classification for filter_malicious, build_graph, analyze_graph, dataset.
"""

from __future__ import annotations

SUSPICION_THRESHOLD = 4

BENIGN_CONTEXT_RULES = frozenset({
    "browser_expected_traffic",
    "svchost_expected_service_net",
    "windows_update_profile",
    "av_expected_activity",
    "popularity_only_activity",
})

HIGH_SIGNAL_RULES = frozenset({
    "hidden_from_pslist",
    "lolbin_network",
    "lsass_full_access",
    "office_lolbin_temporal_chain",
    "inject_plus_lsass_dump",
    "inject_then_c2_combo",
    "hidden_plus_activity",
    "service_user_boundary_cross",
    "untrusted_dll_in_trusted_host",
    "dual_use_tool_with_corroboration",
    "hollowing_like",
    "reflective_pe_like",
    "thread_start_private_exec",
    "sensitive_handle_access",
    "abnormal_parent",
    "suspicious_cmdline",
    "slow_beacon_profile",
    "rare_external_network",
})

# Weak memory-only rules that may downgrade on trusted hosts without corroboration.
WEAK_MEMORY_RULES = frozenset({
    "rwx_injection",
    "nonrwx_exec_private",
})

TRUSTED_HOST_NAMES = frozenset({
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "explorer.exe",
    "winlogon.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
})

BENIGN_HUB_PROCESS_NAMES = frozenset({
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "code.exe",
    "devenv.exe",
    "explorer.exe",
})


def _rule_stages(reasons: set[str], pid_hits: dict | None, pid: int | None) -> set[str]:
    if not pid_hits or pid is None:
        return set()
    stages: set[str] = set()
    for h in pid_hits.get(pid, []):
        if h.rule_id in reasons:
            stages.add(h.stage)
    return stages


def classify_process_zone(
    score: int,
    reasons: list[str],
    *,
    process_name: str = "",
    pid_hits: dict | None = None,
    pid: int | None = None,
    suspicion_threshold: int = SUSPICION_THRESHOLD,
) -> str:
    """
    Return triage_zone: suspect | benign | neutral.
    """
    reason_set = set(reasons or [])
    pname = (process_name or "").lower()

    if reason_set & HIGH_SIGNAL_RULES:
        return "suspect"

    if score < suspicion_threshold:
        return "neutral"

    benign_hits = reason_set & BENIGN_CONTEXT_RULES
    weak_only = reason_set and reason_set <= (BENIGN_CONTEXT_RULES | WEAK_MEMORY_RULES)
    trusted = pname in TRUSTED_HOST_NAMES or pname in BENIGN_HUB_PROCESS_NAMES

    if weak_only and trusted:
        stages = _rule_stages(reason_set, pid_hits, pid)
        if len(stages) <= 1 and not (reason_set & HIGH_SIGNAL_RULES):
            return "benign"

    if benign_hits and not (reason_set - BENIGN_CONTEXT_RULES - WEAK_MEMORY_RULES):
        return "benign"

    if weak_only and trusted:
        return "benign"

    return "suspect"


def triage_zone_rank(zone: str) -> int:
    """Suspect wins over benign over neutral when merging."""
    return {"suspect": 2, "benign": 1, "neutral": 0}.get(zone, 0)


def merge_triage_zone(current: str, new: str) -> str:
    return new if triage_zone_rank(new) > triage_zone_rank(current) else current


def is_suspect_zone(zone: str | None) -> bool:
    return zone == "suspect"


def node_triage_zone(data: dict) -> str:
    """Read triage_zone from node attrs with legacy fallback."""
    zone = data.get("triage_zone")
    if zone in ("suspect", "benign", "neutral"):
        return zone
    if int(data.get("is_suspicious", 0) or 0):
        return "suspect"
    return "neutral"
