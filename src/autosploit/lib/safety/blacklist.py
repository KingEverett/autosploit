from typing import Dict, Set, List, Optional
from dataclasses import dataclass
from pathlib import Path
import json


@dataclass
class BlacklistEntry:
    can_id: int
    reason: str
    severity: str = "high"
    added_by: str = "system"
    added_at: str = ""

    def __post_init__(self):
        if not (0x000 <= self.can_id <= 0x7FF or
                0x00000000 <= self.can_id <= 0x1FFFFFFF):
            raise ValueError(f"Invalid CAN ID: {hex(self.can_id)}")


class BlacklistManager:
    """Manages CAN ID blacklist with persistence."""

    DEFAULT_BLACKLIST = [
        (0x050, "Airbag sensor data", "critical"),
        (0x060, "Airbag control module", "critical"),
        (0x0C4, "Airbag deployment", "critical"),
        (0x200, "Steering angle sensor", "critical"),
        (0x210, "Steering control module", "critical"),
        (0x220, "Power steering", "critical"),
        (0x300, "Brake pressure sensor", "critical"),
        (0x310, "ABS control module", "critical"),
        (0x320, "Electronic stability control", "critical"),
        (0x400, "Engine control - critical", "high"),
        (0x410, "Throttle control", "high"),
    ]

    def __init__(self, load_defaults: bool = True):
        self._entries: Dict[int, BlacklistEntry] = {}

        if load_defaults:
            self._load_defaults()

    def _load_defaults(self) -> None:
        from datetime import datetime

        for can_id, reason, severity in self.DEFAULT_BLACKLIST:
            entry = BlacklistEntry(
                can_id=can_id,
                reason=reason,
                severity=severity,
                added_by="system_default",
                added_at=datetime.now().isoformat()
            )
            self._entries[can_id] = entry

    def add(
        self,
        can_id: int,
        reason: str,
        severity: str = "high",
        added_by: str = "user"
    ) -> None:
        from datetime import datetime

        entry = BlacklistEntry(
            can_id=can_id,
            reason=reason,
            severity=severity,
            added_by=added_by,
            added_at=datetime.now().isoformat()
        )

        self._entries[can_id] = entry

    def remove(self, can_id: int) -> bool:
        if can_id in self._entries:
            del self._entries[can_id]
            return True
        return False

    def is_blacklisted(self, can_id: int) -> bool:
        return can_id in self._entries

    def get(self, can_id: int) -> Optional[BlacklistEntry]:
        return self._entries.get(can_id)

    def get_all(self) -> List[BlacklistEntry]:
        return list(self._entries.values())

    def get_by_severity(self, severity: str) -> List[BlacklistEntry]:
        return [e for e in self._entries.values() if e.severity == severity]

    def save(self, path: Path) -> None:
        data = [
            {
                "can_id": hex(entry.can_id),
                "reason": entry.reason,
                "severity": entry.severity,
                "added_by": entry.added_by,
                "added_at": entry.added_at,
            }
            for entry in self._entries.values()
        ]

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, path: Path, merge: bool = False) -> None:
        if not merge:
            self._entries.clear()

        with open(path, "r") as f:
            data = json.load(f)

        for item in data:
            can_id = int(item["can_id"], 16)

            entry = BlacklistEntry(
                can_id=can_id,
                reason=item["reason"],
                severity=item.get("severity", "high"),
                added_by=item.get("added_by", "imported"),
                added_at=item.get("added_at", "")
            )

            self._entries[can_id] = entry

    def export_to_config(self) -> Dict:
        return {
            "critical_ids": [entry.can_id for entry in self._entries.values()],
            "entries": [
                {
                    "can_id": hex(entry.can_id),
                    "reason": entry.reason,
                    "severity": entry.severity,
                }
                for entry in self._entries.values()
            ]
        }