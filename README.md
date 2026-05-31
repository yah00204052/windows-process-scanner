# windows-process-scanner

A transparent, rule-based behavioral scanner for Windows. Surfaces suspicious processes, autoruns, and network activity using the same TTPs that EDR products look for — implemented in ~700 lines of Python you can read end-to-end.

Not a replacement for an AV product. Designed as a **second-opinion / forensic snapshot tool** for the class of attacks that signature-based engines miss: living-off-the-land binaries (LOLBins), encoded PowerShell, reverse-shell patterns, masquerading binaries, and persistence in non-standard locations.

## What it checks

**Processes** (via `Win32_Process`)
- `suspicious_path` — exe in `%TEMP%`, `%APPDATA%`, `Downloads`, `Public`, `$Recycle.Bin`, or drive root
- `unsigned` / `bad_signature` — Authenticode status
- `encoded_powershell` — `-EncodedCommand` and variants
- `download_cradle` — `IEX`, `DownloadString`, `certutil -urlcache`, `bitsadmin /transfer`
- `hidden_window`, `exec_policy_bypass`
- `office_spawns_shell`, `browser_spawns_shell`, `lsass_child`
- `masquerade` — `svchost.exe`, `lsass.exe` etc. running outside `System32`

**Network** (via `Get-NetTCPConnection`)
- `listening_shell` — `cmd.exe`/`powershell.exe`/`wscript.exe` listening on a port (reverse-shell indicator)
- `shell_outbound` — shell binary with active outbound connections
- `temp_binary_with_network` — exe in suspicious path with outbound traffic

**Persistence** (Run keys, Startup folders, Scheduled Tasks, auto-start Services)
- `persistence_suspicious_path` — autostart entry points to `%TEMP%`/`%APPDATA%`/etc.
- `persistence_lolbin` — `mshta http://...`, `regsvr32 /i:http://...`, etc.
- `persistence_encoded_ps` — encoded PowerShell in an autostart entry
- `persistence_bad_signature` — autostart binary has invalid Authenticode

## How it runs

The scanner is Python 3 but targets Windows. It runs from **WSL** and uses WSL→Windows interop (`powershell.exe`) to query the Windows side. No `pip install`, no Windows-side Python needed.

```bash
git clone https://github.com/yah00204052/windows-process-scanner
cd windows-process-scanner
python3 scanner.py
```

That's it. The scanner spawns short-lived PowerShell subprocesses for each data source (processes, signatures, TCP, persistence), parses JSON back, applies the rules locally, and prints a colored report.

You can also run it from native Windows Python — same code path, swap `python3` for `python`.

### Common invocations

```bash
python3 scanner.py                          # full scan, ~8s
python3 scanner.py --no-signatures          # ~3s (skips Authenticode batch)
python3 scanner.py --min-severity high      # quiet — only high/critical findings
python3 scanner.py --min-severity critical  # wake-me-up mode
python3 scanner.py --json > scan.json       # machine-readable
python3 scanner.py --no-persistence         # skip autoruns scan
python3 scanner.py --no-network             # skip TCP enum
python3 scanner.py --no-allowlist           # show raw findings (no FP suppression)
python3 scanner.py --help                   # all flags
```

## Allowlist

Some legitimate software exhibits the same behaviors as malware (browser extensions that pipe through `cmd.exe`, app updaters that drop installers in `%TEMP%`). Edit `allowlist.json` to suppress known-good matches:

```json
{
  "suppressions": [
    {
      "rule": "browser_spawns_shell",
      "comment": "Why this is legit",
      "match": {
        "cmdline_contains": "\\Program Files\\YourApp\\"
      }
    }
  ]
}
```

Match fields are AND-ed within an entry: `exe_contains`, `cmdline_contains`, `name_equals`, `parent_equals`. Multiple entries are OR-ed.

## Architecture

```
scanner.py                  CLI entry point
allowlist.json              Suppression rules (user-editable)
detector/
  processes.py              Win32_Process enumeration
  signatures.py             Get-AuthenticodeSignature (batched)
  network.py                Get-NetTCPConnection
  persistence.py            Run keys + Startup + Scheduled Tasks + Services
  allowlist.py              Suppression engine
  heuristics.py             All rules + ProcessReport / PersistenceReport
  report.py                 Colored text + JSON output
```

Each data source is one short-lived PowerShell subprocess returning JSON. Rules are pure Python over the parsed dataclasses — easy to test, easy to extend.

## Limitations

- **Snapshot, not real-time.** Catches what's running now; misses transient malware that exits before you scan.
- **No file scanning.** Doesn't read file bytes, doesn't compute hashes, doesn't match signatures against malware DBs.
- **No removal.** Findings are read-only; you decide what to do.
- **WSL→Windows interop required** when running from WSL. If interop is disabled, the scanner exits with a clear error.
- **Administrator visibility.** Without elevation, processes owned by other users are hidden from `Win32_Process`. Personal-PC scans usually don't care; multi-user systems do.

## License

MIT
