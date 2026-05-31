from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from .allowlist import Allowlist
from .network import TcpConn
from .persistence import PersistenceEntry
from .processes import ProcessInfo

SEVERITY_RANK = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str


@dataclass
class ProcessReport:
    proc: ProcessInfo
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(SEVERITY_RANK[f.severity] for f in self.findings)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "clean"
        top = max(SEVERITY_RANK[f.severity] for f in self.findings)
        return next(k for k, v in SEVERITY_RANK.items() if v == top)


@dataclass
class PersistenceReport:
    entry: PersistenceEntry
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(SEVERITY_RANK[f.severity] for f in self.findings)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "clean"
        top = max(SEVERITY_RANK[f.severity] for f in self.findings)
        return next(k for k, v in SEVERITY_RANK.items() if v == top)


SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\\AppData\\Local\\Temp\\", re.I),
    re.compile(r"\\AppData\\Roaming\\Temp\\", re.I),
    re.compile(r"\\Windows\\Temp\\", re.I),
    re.compile(r"^[A-Z]:\\Temp\\", re.I),
    re.compile(r"\\Downloads\\.*\.(exe|scr|bat|cmd|ps1|vbs|js|hta|jar)$", re.I),
    re.compile(r"^[A-Z]:\\Users\\Public\\", re.I),
    re.compile(r"\\\$Recycle\.Bin\\", re.I),
    re.compile(r"^[A-Z]:\\ProgramData\\[^\\]+\.exe$", re.I),
    re.compile(r"^[A-Z]:\\[^\\]+\.exe$", re.I),  # exe at drive root
]

# Per-binary list of legitimate Windows paths (lowercase, partial match).
# A process named like a system binary running from anywhere else is suspicious.
SYSTEM_BINARY_PATHS = {
    "svchost.exe":      ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "lsass.exe":        ("\\windows\\system32\\",),
    "csrss.exe":        ("\\windows\\system32\\",),
    "winlogon.exe":     ("\\windows\\system32\\",),
    "services.exe":     ("\\windows\\system32\\",),
    "smss.exe":         ("\\windows\\system32\\",),
    "wininit.exe":      ("\\windows\\system32\\",),
    "spoolsv.exe":      ("\\windows\\system32\\",),
    "taskhostw.exe":    ("\\windows\\system32\\",),
    "dwm.exe":          ("\\windows\\system32\\",),
    "fontdrvhost.exe":  ("\\windows\\system32\\",),
    "sihost.exe":       ("\\windows\\system32\\",),
    "explorer.exe":     ("\\windows\\explorer.exe", "\\windows\\syswow64\\explorer.exe"),
}

OFFICE_NAMES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
}
BROWSER_NAMES = {
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
    "brave.exe", "iexplore.exe",
}
SHELL_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
}

ENCODED_PS = re.compile(r"(?:^|\s)-(e|en|enc|enco|encod|encode|encodedcommand)\b", re.I)
DOWNLOAD_CRADLE = re.compile(
    r"(IEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|"
    r"Invoke-WebRequest|certutil.*-urlcache|bitsadmin.*\/transfer)",
    re.I,
)
HIDDEN_WINDOW = re.compile(r"-w(?:indowstyle)?\s+hidden", re.I)
EXEC_BYPASS = re.compile(r"-(?:ep|executionpolicy)\s+bypass", re.I)


def evaluate(
    procs: list[ProcessInfo],
    signatures: Mapping[str, str] | None = None,
    allowlist: Allowlist | None = None,
    connections: Mapping[int, list[TcpConn]] | None = None,
) -> tuple[list[ProcessReport], int]:
    """Run all rules. Returns (reports, suppressed_count)."""
    signatures = signatures or {}
    connections = connections or {}
    suppressed_total = 0
    reports = []
    for p in procs:
        r = ProcessReport(proc=p)
        _check_path(r)
        _check_signature(r, signatures)
        _check_cmdline(r)
        _check_parent_child(r)
        _check_masquerade(r)
        _check_network(r, connections.get(p.pid, []))
        if allowlist and r.findings:
            kept = []
            for f in r.findings:
                if allowlist.is_suppressed(f.rule, r.proc):
                    suppressed_total += 1
                else:
                    kept.append(f)
            r.findings = kept
        reports.append(r)
    return reports, suppressed_total


def _check_path(r: ProcessReport) -> None:
    exe = r.proc.exe
    if not exe:
        return
    for pat in SUSPICIOUS_PATH_PATTERNS:
        if pat.search(exe):
            r.findings.append(
                Finding("suspicious_path", "high", f"Executable in suspicious location: {exe}")
            )
            return


def _check_signature(r: ProcessReport, signatures: Mapping[str, str]) -> None:
    exe = r.proc.exe
    if not exe:
        return
    status = signatures.get(exe)
    if status is None:
        return
    if status == "NotSigned":
        # Many legit tools are unsigned; keep this low and let it stack with other findings.
        r.findings.append(Finding("unsigned", "low", "Binary is not Authenticode-signed"))
    elif status in {"HashMismatch", "NotTrusted", "UnknownError"}:
        r.findings.append(Finding("bad_signature", "critical", f"Signature status: {status}"))


def _check_cmdline(r: ProcessReport) -> None:
    cmd = r.proc.cmdline
    if not cmd:
        return
    name = r.proc.name.lower()
    is_ps = "powershell" in name or name == "pwsh.exe"

    if is_ps and ENCODED_PS.search(cmd):
        r.findings.append(Finding("encoded_powershell", "high", "Encoded PowerShell command"))
    if DOWNLOAD_CRADLE.search(cmd):
        r.findings.append(Finding("download_cradle", "high", "Download cradle in command line"))
    if HIDDEN_WINDOW.search(cmd):
        r.findings.append(Finding("hidden_window", "medium", "Hidden window flag"))
    if EXEC_BYPASS.search(cmd):
        r.findings.append(Finding("exec_policy_bypass", "medium", "ExecutionPolicy Bypass"))


def _check_parent_child(r: ProcessReport) -> None:
    parent = (r.proc.parent_name or "").lower()
    name = r.proc.name.lower()
    if parent in OFFICE_NAMES and name in SHELL_NAMES:
        r.findings.append(
            Finding("office_spawns_shell", "critical", f"{parent} spawned {name}")
        )
    if parent in BROWSER_NAMES and name in SHELL_NAMES:
        r.findings.append(
            Finding("browser_spawns_shell", "critical", f"{parent} spawned {name}")
        )
    if parent == "lsass.exe":
        r.findings.append(
            Finding("lsass_child", "critical", "Process spawned by lsass.exe (highly unusual)")
        )


_NETWORK_SHELL_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
}


def _is_loopback(addr: str) -> bool:
    # 0.0.0.0 / :: are "any interface" — exactly what reverse shells bind to, NOT loopback.
    return not addr or addr.startswith("127.") or addr == "::1"


def _check_network(r: ProcessReport, conns: list[TcpConn]) -> None:
    if not conns:
        return

    name = r.proc.name.lower()
    is_shell = name in _NETWORK_SHELL_NAMES
    already_flagged_path = any(f.rule == "suspicious_path" for f in r.findings)

    listening_external = [
        c for c in conns if c.state == "Listen" and not _is_loopback(c.local_addr)
    ]
    established_external = [
        c for c in conns if c.state == "Established" and not _is_loopback(c.remote_addr)
    ]

    if is_shell and listening_external:
        ports = sorted({c.local_port for c in listening_external})
        r.findings.append(
            Finding(
                "listening_shell",
                "critical",
                f"{name} listening on port(s) {', '.join(str(p) for p in ports)} — strong reverse-shell indicator",
            )
        )

    if is_shell and established_external:
        remotes = sorted({f"{c.remote_addr}:{c.remote_port}" for c in established_external})[:3]
        r.findings.append(
            Finding(
                "shell_outbound",
                "high",
                f"{name} has outbound connection(s): {', '.join(remotes)}",
            )
        )

    if already_flagged_path and established_external:
        remotes = sorted({f"{c.remote_addr}:{c.remote_port}" for c in established_external})[:3]
        r.findings.append(
            Finding(
                "temp_binary_with_network",
                "high",
                f"Binary in suspicious location has outbound connection(s): {', '.join(remotes)}",
            )
        )


def _check_masquerade(r: ProcessReport) -> None:
    name = r.proc.name.lower()
    exe = (r.proc.exe or "").lower()
    allowed = SYSTEM_BINARY_PATHS.get(name)
    if allowed and exe and not any(a in exe for a in allowed):
        r.findings.append(
            Finding(
                "masquerade",
                "critical",
                f"{name} running from non-system path: {r.proc.exe}",
            )
        )


# -- Persistence rules --------------------------------------------------------

_LOLBIN_PERSISTENCE = re.compile(
    r"(rundll32.*\bjavascript:|"
    r"mshta\b[^|]*https?://|"
    r"regsvr32\b[^|]*\/i:https?://|"
    r"certutil\b[^|]*-urlcache|"
    r"bitsadmin\b[^|]*\/transfer)",
    re.I,
)


def evaluate_persistence(
    entries: list[PersistenceEntry],
    signatures: Mapping[str, str] | None = None,
) -> list[PersistenceReport]:
    signatures = signatures or {}
    reports = []
    for e in entries:
        r = PersistenceReport(entry=e)
        _check_persistence_path(r)
        _check_persistence_lolbin(r)
        _check_persistence_encoded_ps(r)
        _check_persistence_signature(r, signatures)
        reports.append(r)
    return reports


def _check_persistence_path(r: PersistenceReport) -> None:
    exe = r.entry.exe
    if not exe:
        return
    for pat in SUSPICIOUS_PATH_PATTERNS:
        if pat.search(exe):
            r.findings.append(
                Finding(
                    "persistence_suspicious_path",
                    "high",
                    f"{r.entry.source} entry points to suspicious location: {exe}",
                )
            )
            return


def _check_persistence_lolbin(r: PersistenceReport) -> None:
    if _LOLBIN_PERSISTENCE.search(r.entry.command):
        snippet = r.entry.command[:120]
        r.findings.append(
            Finding(
                "persistence_lolbin",
                "critical",
                f"{r.entry.source} entry uses LOLBin pattern: {snippet}",
            )
        )


def _check_persistence_encoded_ps(r: PersistenceReport) -> None:
    cmd_lower = r.entry.command.lower()
    if ("powershell" in cmd_lower or "pwsh" in cmd_lower) and ENCODED_PS.search(r.entry.command):
        r.findings.append(
            Finding(
                "persistence_encoded_ps",
                "critical",
                f"{r.entry.source} entry runs encoded PowerShell",
            )
        )


def _check_persistence_signature(r: PersistenceReport, signatures: Mapping[str, str]) -> None:
    exe = r.entry.exe
    if not exe:
        return
    status = signatures.get(exe)
    if status in {"HashMismatch", "NotTrusted", "UnknownError"}:
        r.findings.append(
            Finding(
                "persistence_bad_signature",
                "critical",
                f"{r.entry.source} entry has invalid signature ({status}): {exe}",
            )
        )
