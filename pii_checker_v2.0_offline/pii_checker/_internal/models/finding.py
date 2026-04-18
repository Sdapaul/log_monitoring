from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Finding:
    finding_id: str        # sha256[:12] of (source_file + line_no)
    category: str          # 'PII_EXPOSURE'|'EXCESSIVE_ACCESS'|'AFTER_HOURS'|'BULK_EXPORT'
    severity: str          # 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'
    user_id: str
    timestamp: datetime | None
    pii_types: list[str] = field(default_factory=list)
    evidence: str = ''     # redacted snippet
    raw_reference: str = ''  # "file.log:1234"
    score: float = 0.0
    details: dict = field(default_factory=dict)

    @property
    def timestamp_str(self) -> str:
        if self.timestamp:
            return self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        return '알 수 없음'

    @property
    def pii_types_str(self) -> str:
        return ', '.join(self.pii_types) if self.pii_types else '-'
