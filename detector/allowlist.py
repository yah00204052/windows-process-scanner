from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .processes import ProcessInfo


@dataclass
class Suppression:
    rule: str
    exe_contains: str | None = None
    cmdline_contains: str | None = None
    name_equals: str | None = None
    parent_equals: str | None = None
    comment: str = ""

    def matches(self, rule_name: str, proc: ProcessInfo) -> bool:
        if self.rule != rule_name:
            return False
        if self.exe_contains and self.exe_contains.lower() not in (proc.exe or "").lower():
            return False
        if self.cmdline_contains and self.cmdline_contains.lower() not in proc.cmdline.lower():
            return False
        if self.name_equals and self.name_equals.lower() != proc.name.lower():
            return False
        if self.parent_equals and self.parent_equals.lower() != (proc.parent_name or "").lower():
            return False
        return True


@dataclass
class Allowlist:
    suppressions: list[Suppression]

    def is_suppressed(self, rule_name: str, proc: ProcessInfo) -> bool:
        return any(s.matches(rule_name, proc) for s in self.suppressions)

    @classmethod
    def empty(cls) -> "Allowlist":
        return cls([])

    @classmethod
    def load(cls, path: Path) -> "Allowlist":
        if not path.exists():
            return cls.empty()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            sys.stderr.write(f"warning: failed to load allowlist {path}: {e}\n")
            return cls.empty()

        sups: list[Suppression] = []
        for i, raw in enumerate(data.get("suppressions", [])):
            if "rule" not in raw:
                sys.stderr.write(f"warning: allowlist entry #{i} missing 'rule', skipping\n")
                continue
            match = raw.get("match", {})
            sups.append(
                Suppression(
                    rule=raw["rule"],
                    exe_contains=match.get("exe_contains"),
                    cmdline_contains=match.get("cmdline_contains"),
                    name_equals=match.get("name_equals"),
                    parent_equals=match.get("parent_equals"),
                    comment=raw.get("comment", ""),
                )
            )
        return cls(sups)
