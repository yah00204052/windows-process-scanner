from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class TcpConn:
    pid: int
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str  # 'Listen', 'Established', 'TimeWait', etc.


# Get-NetTCPConnection State enum (MSFT_NetTCPConnection).
_STATE_NAMES = {
    1: "Closed",  2: "Listen",      3: "SynSent",    4: "SynReceived",
    5: "Established", 6: "FinWait1", 7: "FinWait2",  8: "CloseWait",
    9: "Closing", 10: "LastAck",    11: "TimeWait", 12: "DeleteTCB",
    100: "Bound",
}


_PS_TCP = """
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Get-NetTCPConnection |
  Select-Object @{n='Pid';       e={[int]$_.OwningProcess}},
                @{n='LocalAddr'; e={$_.LocalAddress}},
                @{n='LocalPort'; e={[int]$_.LocalPort}},
                @{n='RemoteAddr';e={$_.RemoteAddress}},
                @{n='RemotePort';e={[int]$_.RemotePort}},
                @{n='State';     e={[int]$_.State}} |
  ConvertTo-Json -Compress
"""


def enumerate_tcp_by_pid() -> dict[int, list[TcpConn]]:
    """Return {pid: [TcpConn, ...]}. Empty dict on failure — network rules then no-op."""
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_TCP],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}

    out = result.stdout.strip()
    if not out:
        return {}

    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        return {}

    if isinstance(rows, dict):
        rows = [rows]

    by_pid: dict[int, list[TcpConn]] = defaultdict(list)
    for row in rows:
        pid = row.get("Pid")
        if pid is None:
            continue
        by_pid[pid].append(
            TcpConn(
                pid=pid,
                local_addr=row.get("LocalAddr") or "",
                local_port=row.get("LocalPort") or 0,
                remote_addr=row.get("RemoteAddr") or "",
                remote_port=row.get("RemotePort") or 0,
                state=_STATE_NAMES.get(row.get("State", 0), "Unknown"),
            )
        )
    return dict(by_pid)
