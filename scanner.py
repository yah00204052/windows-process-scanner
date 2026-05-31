#!/usr/bin/env python3
"""Behavioral process scanner — flags suspicious Windows processes.

Runs from WSL via Windows interop. No external Python dependencies required.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from detector.allowlist import Allowlist
from detector.heuristics import evaluate, evaluate_persistence
from detector.network import enumerate_tcp_by_pid
from detector.persistence import enumerate_persistence
from detector.processes import ProcessEnumerationError, enumerate_processes
from detector.report import print_persistence_report, print_report, to_json
from detector.signatures import batch_check_signatures

DEFAULT_ALLOWLIST = Path(__file__).resolve().parent / "allowlist.json"


def _powershell_admin_status() -> str | None:
    """Return 'true', 'false', or None if powershell.exe is unreachable."""
    try:
        result = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "([Security.Principal.WindowsPrincipal]"
                "[Security.Principal.WindowsIdentity]::GetCurrent())"
                ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip().lower() or None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan running Windows processes for suspicious behavior.",
        epilog=(
            "Launch your WSL terminal from an elevated Windows Terminal "
            "to give the spawned PowerShell Administrator visibility."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Suppress findings below this severity (default: low)",
    )
    parser.add_argument(
        "--all", action="store_true", help="Include clean processes in output"
    )
    parser.add_argument(
        "--no-signatures",
        action="store_true",
        help="Skip Authenticode checks (faster — saves several seconds)",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Skip TCP connection enumeration",
    )
    parser.add_argument(
        "--no-persistence",
        action="store_true",
        help="Skip autoruns / persistence scan (Run keys, Startup, Tasks, Services)",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST,
        help=f"Path to allowlist JSON (default: {DEFAULT_ALLOWLIST.name})",
    )
    parser.add_argument(
        "--no-allowlist",
        action="store_true",
        help="Disable allowlist filtering — show raw findings",
    )
    args = parser.parse_args()

    admin = _powershell_admin_status()
    if admin is None:
        sys.stderr.write(
            "error: powershell.exe is not reachable from this environment.\n"
            "  This tool requires WSL with Windows interop enabled (the default),\n"
            "  or to be run on Windows directly.\n"
        )
        return 2
    if admin != "true" and not args.json:
        sys.stderr.write(
            "warning: spawned PowerShell is not Administrator — some processes will be hidden.\n"
            "  Restart your WSL terminal from an elevated Windows Terminal for full visibility.\n\n"
        )

    try:
        procs = enumerate_processes()
    except ProcessEnumerationError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1

    persistence = [] if args.no_persistence else enumerate_persistence()
    conns = {} if args.no_network else enumerate_tcp_by_pid()

    if args.no_signatures:
        sigs: dict[str, str] = {}
    else:
        sig_paths = [p.exe for p in procs] + [e.exe for e in persistence]
        sigs = batch_check_signatures(sig_paths)

    allowlist = Allowlist.empty() if args.no_allowlist else Allowlist.load(args.allowlist)
    reports, suppressed = evaluate(procs, sigs, allowlist, connections=conns)
    persistence_reports = evaluate_persistence(persistence, sigs)

    if args.json:
        print(to_json(reports, args.min_severity, args.all, persistence=persistence_reports))
    else:
        print_report(reports, args.min_severity, args.all, suppressed=suppressed)
        if persistence_reports:
            print_persistence_report(persistence_reports, args.min_severity, args.all)
    return 0


if __name__ == "__main__":
    sys.exit(main())
