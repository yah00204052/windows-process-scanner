from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass
class ProcessInfo:
    pid: int
    ppid: int | None
    name: str
    exe: str | None
    cmdline: str
    create_time: int | None
    parent_name: str | None


class ProcessEnumerationError(RuntimeError):
    """Raised when we cannot obtain a process list from Windows."""


_PS_LIST_PROCESSES = """
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Get-CimInstance -ClassName Win32_Process |
  Select-Object @{n='Pid';        e={[int]$_.ProcessId}},
                @{n='Ppid';       e={[int]$_.ParentProcessId}},
                @{n='Name';       e={$_.Name}},
                @{n='Exe';        e={$_.ExecutablePath}},
                @{n='CommandLine';e={$_.CommandLine}},
                @{n='CreationDate';e={
                    if ($_.CreationDate) {
                        ([DateTimeOffset]$_.CreationDate).ToUnixTimeSeconds()
                    } else { $null }
                }} |
  ConvertTo-Json -Compress -Depth 3
"""


def enumerate_processes() -> list[ProcessInfo]:
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_LIST_PROCESSES],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError as e:
        raise ProcessEnumerationError(
            "powershell.exe not reachable. WSL→Windows interop must be enabled.\n"
            "  Check /etc/wsl.conf contains [interop]\\nenabled=true, then run `wsl --shutdown` from Windows."
        ) from e
    except subprocess.TimeoutExpired as e:
        raise ProcessEnumerationError("Win32_Process query timed out after 60s") from e

    if result.returncode != 0 or not result.stdout.strip():
        raise ProcessEnumerationError(
            f"PowerShell process enumeration failed: {result.stderr.strip() or 'no output'}"
        )

    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ProcessEnumerationError(f"PowerShell output was not valid JSON: {e}") from e

    if isinstance(rows, dict):
        rows = [rows]

    by_pid: dict[int, dict] = {
        row["Pid"]: row for row in rows if row.get("Pid") is not None
    }
    out: list[ProcessInfo] = []
    for row in by_pid.values():
        parent = by_pid.get(row.get("Ppid"))
        out.append(
            ProcessInfo(
                pid=row["Pid"],
                ppid=row.get("Ppid"),
                name=row.get("Name") or "",
                exe=row.get("Exe") or None,
                cmdline=row.get("CommandLine") or "",
                create_time=row.get("CreationDate"),
                parent_name=(parent.get("Name") if parent else None),
            )
        )
    return out
