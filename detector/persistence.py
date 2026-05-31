from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass


@dataclass
class PersistenceEntry:
    source: str   # e.g. "HKLM\\Run", "Startup folder (user)", "Scheduled Task", "Service (auto-start)"
    name: str     # value name / filename / task path / service name
    command: str  # full command line that gets executed

    @property
    def exe(self) -> str | None:
        """Best-effort extraction of the executable path from the command line."""
        if not self.command:
            return None
        try:
            tokens = shlex.split(self.command, posix=False)
            if tokens:
                return tokens[0].strip('"')
        except ValueError:
            pass
        return self.command.split(" ", 1)[0]


_PS_PERSISTENCE = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$entries = New-Object System.Collections.Generic.List[PSObject]

# Registry Run / RunOnce keys
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
    if (Test-Path $k) {
        $item = Get-Item $k
        foreach ($n in $item.GetValueNames()) {
            $v = $item.GetValue($n)
            if ($v) {
                $entries.Add([PSCustomObject]@{
                    Source  = $k.Replace('HKLM:\','HKLM\').Replace('HKCU:\','HKCU\')
                    Name    = $n
                    Command = [string]$v
                })
            }
        }
    }
}

# Startup folders
$startupDirs = @(
    @{ Path = [Environment]::GetFolderPath('Startup');       Label = 'Startup folder (user)'   },
    @{ Path = [Environment]::GetFolderPath('CommonStartup'); Label = 'Startup folder (system)' }
)
foreach ($d in $startupDirs) {
    if ($d.Path -and (Test-Path $d.Path)) {
        Get-ChildItem -LiteralPath $d.Path -File | ForEach-Object {
            $entries.Add([PSCustomObject]@{
                Source  = $d.Label
                Name    = $_.Name
                Command = $_.FullName
            })
        }
    }
}

# Scheduled Tasks (enabled only)
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
    $task = $_
    foreach ($a in $task.Actions) {
        $exe  = if ($a.Execute)   { $a.Execute }   else { '' }
        $argv = if ($a.Arguments) { ' ' + $a.Arguments } else { '' }
        $cmd  = ($exe + $argv).Trim()
        if ($cmd) {
            $entries.Add([PSCustomObject]@{
                Source  = 'Scheduled Task'
                Name    = ($task.TaskPath + $task.TaskName)
                Command = $cmd
            })
        }
    }
}

# Services (auto-start only — manual/disabled aren't persistence)
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } | ForEach-Object {
    $entries.Add([PSCustomObject]@{
        Source  = 'Service (auto-start)'
        Name    = $_.Name
        Command = $_.PathName
    })
}

$entries | ConvertTo-Json -Compress
"""


def enumerate_persistence() -> list[PersistenceEntry]:
    """One PowerShell call across all four persistence surfaces. Empty list on failure."""
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_PERSISTENCE],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    out = result.stdout.strip()
    if not out:
        return []

    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        return []

    if isinstance(rows, dict):
        rows = [rows]

    return [
        PersistenceEntry(
            source=r.get("Source") or "",
            name=r.get("Name") or "",
            command=r.get("Command") or "",
        )
        for r in rows
    ]
