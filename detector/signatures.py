from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable


_PS_CHECK_SIGS = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$paths = [Console]::In.ReadToEnd() -split "`r?`n" | Where-Object { $_ }
$paths | ForEach-Object {
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction Stop
        [PSCustomObject]@{ Path = $_; Status = $s.Status.ToString() }
    } catch { }
} | ConvertTo-Json -Compress
"""


def batch_check_signatures(paths: Iterable[str | None]) -> dict[str, str]:
    """Return {path: status} from Get-AuthenticodeSignature, one PowerShell call total.

    Status strings are PowerShell SignatureStatus values:
    Valid, NotSigned, HashMismatch, NotTrusted, UnknownError, Incompatible, etc.
    """
    unique = sorted({p for p in paths if p})
    if not unique:
        return {}

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_CHECK_SIGS],
            input="\n".join(unique),
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}

    out = result.stdout.strip()
    if not out:
        return {}

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {}

    if isinstance(data, dict):
        data = [data]
    return {row["Path"]: row.get("Status", "Unknown") for row in data if row.get("Path")}
