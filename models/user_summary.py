from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from models.finding import Finding


@dataclass
class UserSummary:
    user_id: str
    total_events: int = 0
    pii_event_count: int = 0
    pii_types_seen: set = field(default_factory=set)
    max_queries_per_hour: int = 0
    max_queries_per_day: int = 0
    peak_hour: str = ''          # "2024-01-15 14:00"
    peak_day: str = ''           # "2024-01-15"
    after_hours_count: int = 0
    bulk_export_count: int = 0
    unique_targets_per_day: int = 0
    risk_score: float = 0.0
    risk_level: str = 'LOW'      # 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'
    findings: list[Finding] = field(default_factory=list)
    justification_text: str = ''  # HR annotation placeholder

    # ── 쿼리 결과 기반 개인정보 노출량 ───────────────────────
    total_pii_records_exposed: int = 0     # 기간 내 실효 노출 총 건수
    max_single_query_exposure: int = 0     # 단일 쿼리 최대 노출 건수
    unknown_exposure_query_count: int = 0  # 건수 미상인 PII SELECT 쿼리 수
    select_pii_query_count: int = 0        # SELECT절 PII 노출 쿼리 수
    search_only_query_count: int = 0       # WHERE절만 PII 사용 (검색조건) 쿼리 수

    @property
    def flagged_event_count(self) -> int:
        return len(self.findings)

    @property
    def critical_finding_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'CRITICAL')

    @property
    def high_finding_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'HIGH')

    @property
    def pii_types_str(self) -> str:
        return ', '.join(sorted(self.pii_types_seen)) if self.pii_types_seen else '-'

    @property
    def pii_finding_count(self) -> int:
        return sum(1 for f in self.findings if f.category == 'PII_EXPOSURE')

    @property
    def excess_finding_count(self) -> int:
        return sum(1 for f in self.findings if f.category == 'EXCESSIVE_ACCESS')

    @property
    def exposure_risk_level(self) -> str:
        """노출량만으로 판단한 위험 등급"""
        if self.total_pii_records_exposed >= 50_000:
            return 'CRITICAL'
        elif self.total_pii_records_exposed >= 10_000:
            return 'HIGH'
        elif self.total_pii_records_exposed >= 1_000:
            return 'MEDIUM'
        return 'LOW'

    @property
    def exposure_display(self) -> str:
        """노출량 표시 문자열"""
        known = f"{self.total_pii_records_exposed:,}건"
        unknown = f" + 건수미확인 {self.unknown_exposure_query_count}건" if self.unknown_exposure_query_count > 0 else ""
        return known + unknown
