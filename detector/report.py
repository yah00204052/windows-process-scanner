from __future__ import annotations

import json

from .heuristics import PersistenceReport, ProcessReport, SEVERITY_RANK

COLORS = {
    "critical": "\033[1;91m",
    "high":     "\033[91m",
    "medium":   "\033[93m",
    "low":      "\033[96m",
    "clean":    "\033[90m",
    "reset":    "\033[0m",
    "bold":     "\033[1m",
}


def _filter(reports: list[ProcessReport], min_severity: str, include_clean: bool):
    threshold = SEVERITY_RANK[min_severity]
    out = []
    for r in reports:
        if not r.findings and not include_clean:
            continue
        if SEVERITY_RANK[r.max_severity] < threshold:
            continue
        out.append(r)
    return out


def print_report(
    reports: list[ProcessReport],
    min_severity: str = "low",
    include_clean: bool = False,
    suppressed: int = 0,
) -> None:
    flagged = _filter(reports, min_severity, include_clean)
    flagged.sort(key=lambda r: (-SEVERITY_RANK[r.max_severity], -r.score, r.proc.name.lower()))

    counts = {k: 0 for k in SEVERITY_RANK}
    for r in reports:
        counts[r.max_severity] += 1

    print(f"\n{COLORS['bold']}Scanned {len(reports)} processes{COLORS['reset']}")
    for sev in ("critical", "high", "medium", "low"):
        if counts[sev]:
            print(f"  {COLORS[sev]}{sev:>8}{COLORS['reset']}: {counts[sev]}")
    print(f"  {COLORS['clean']}   clean{COLORS['reset']}: {counts['clean']}")
    if suppressed:
        print(f"  {COLORS['clean']}suppressed by allowlist: {suppressed}{COLORS['reset']}")
    print()

    if not flagged:
        print(f"{COLORS['low']}No findings at severity >= {min_severity}{COLORS['reset']}")
        return

    for r in flagged:
        sev = r.max_severity
        c = COLORS.get(sev, "")
        parent = r.proc.parent_name or "?"
        print(
            f"{c}[{sev.upper()}]{COLORS['reset']} pid={r.proc.pid} "
            f"{COLORS['bold']}{r.proc.name}{COLORS['reset']}  (parent={parent})"
        )
        if r.proc.exe:
            print(f"        path: {r.proc.exe}")
        if r.proc.cmdline:
            cmd = r.proc.cmdline
            if len(cmd) > 240:
                cmd = cmd[:237] + "..."
            print(f"        cmd:  {cmd}")
        for f in r.findings:
            fc = COLORS.get(f.severity, "")
            print(f"          {fc}- [{f.severity}] {f.rule}{COLORS['reset']}: {f.detail}")
        print()


def _filter_persistence(
    reports: list[PersistenceReport], min_severity: str, include_clean: bool
) -> list[PersistenceReport]:
    threshold = SEVERITY_RANK[min_severity]
    out = []
    for r in reports:
        if not r.findings and not include_clean:
            continue
        if SEVERITY_RANK[r.max_severity] < threshold:
            continue
        out.append(r)
    return out


def print_persistence_report(
    reports: list[PersistenceReport], min_severity: str = "low", include_clean: bool = False
) -> None:
    flagged = _filter_persistence(reports, min_severity, include_clean)
    flagged.sort(key=lambda r: (-SEVERITY_RANK[r.max_severity], -r.score, r.entry.source))

    counts = {k: 0 for k in SEVERITY_RANK}
    for r in reports:
        counts[r.max_severity] += 1

    print(f"\n{COLORS['bold']}Checked {len(reports)} persistence entries{COLORS['reset']}")
    for sev in ("critical", "high", "medium", "low"):
        if counts[sev]:
            print(f"  {COLORS[sev]}{sev:>8}{COLORS['reset']}: {counts[sev]}")
    print(f"  {COLORS['clean']}   clean{COLORS['reset']}: {counts['clean']}")
    print()

    if not flagged:
        print(f"{COLORS['low']}No persistence findings at severity >= {min_severity}{COLORS['reset']}")
        return

    for r in flagged:
        sev = r.max_severity
        c = COLORS.get(sev, "")
        print(
            f"{c}[{sev.upper()}]{COLORS['reset']} {COLORS['bold']}{r.entry.source}{COLORS['reset']}: {r.entry.name}"
        )
        cmd = r.entry.command
        if len(cmd) > 240:
            cmd = cmd[:237] + "..."
        print(f"        command: {cmd}")
        for f in r.findings:
            fc = COLORS.get(f.severity, "")
            print(f"          {fc}- [{f.severity}] {f.rule}{COLORS['reset']}: {f.detail}")
        print()


def to_json(
    reports: list[ProcessReport],
    min_severity: str = "low",
    include_clean: bool = False,
    persistence: list[PersistenceReport] | None = None,
) -> str:
    flagged = _filter(reports, min_severity, include_clean)
    proc_out = []
    for r in flagged:
        proc_out.append({
            "pid": r.proc.pid,
            "ppid": r.proc.ppid,
            "name": r.proc.name,
            "parent_name": r.proc.parent_name,
            "exe": r.proc.exe,
            "cmdline": r.proc.cmdline,
            "create_time": r.proc.create_time,
            "severity": r.max_severity,
            "score": r.score,
            "findings": [
                {"rule": f.rule, "severity": f.severity, "detail": f.detail}
                for f in r.findings
            ],
        })

    pers_out = []
    if persistence:
        for r in _filter_persistence(persistence, min_severity, include_clean):
            pers_out.append({
                "source": r.entry.source,
                "name": r.entry.name,
                "command": r.entry.command,
                "exe": r.entry.exe,
                "severity": r.max_severity,
                "score": r.score,
                "findings": [
                    {"rule": f.rule, "severity": f.severity, "detail": f.detail}
                    for f in r.findings
                ],
            })

    return json.dumps({"processes": proc_out, "persistence": pers_out}, indent=2)
