from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PiiHit:
    pii_type: str          # e.g. 'RRN', 'PHONE', 'CREDIT_CARD'
    severity: str          # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    redacted_value: str    # masked representation for reports
    match_start: int
    match_end: int


@dataclass
class LogEvent:
    raw_line: str
    source_file: str
    line_no: int
    timestamp: datetime | None = None
    user_id: str | None = None
    ip_address: str | None = None
    action: str | None = None
    target: str | None = None        # table name, URL path, resource
    query_text: str | None = None    # full SQL or request body
    log_type: str = 'unknown'        # 'syslog'|'app'|'db'|'web'|'unknown'
    pii_hits: list[PiiHit] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    # ── 쿼리 결과 기반 개인정보 노출량 ───────────────────────
    result_row_count: int | None = None      # 쿼리 결과 건수 (None=알 수 없음)
    pii_select_fields: list[str] = field(default_factory=list)  # SELECT절 PII 컬럼
    pii_where_fields: list[str] = field(default_factory=list)   # WHERE절 PII 컬럼(검색조건)
    is_select_star: bool = False             # SELECT * 여부
    is_sensitive_table: bool = False         # 민감 테이블 대상
    effective_pii_exposure: int | None = None  # 실효 노출량 = 건수 × PII필드수
    exposure_type: str = 'UNKNOWN'           # 'FULL_EXPOSURE'|'PARTIAL_EXPOSURE'|'SEARCH_ONLY'|'NONE'

    @property
    def has_pii(self) -> bool:
        return len(self.pii_hits) > 0

    @property
    def has_select_pii(self) -> bool:
        """SELECT 절에 PII 컬럼이 있거나 SELECT * 인 경우"""
        return bool(self.pii_select_fields) or self.is_select_star

    @property
    def pii_select_count(self) -> int:
        if self.is_select_star:
            return 5 if self.is_sensitive_table else 3
        return len(self.pii_select_fields)

    @property
    def max_pii_severity(self) -> str | None:
        if not self.pii_hits:
            return None
        order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for sev in order:
            if any(h.severity == sev for h in self.pii_hits):
                return sev
        return None

    @property
    def exposure_display(self) -> str:
        """보고서용 노출량 표시 문자열"""
        if self.exposure_type in ('NONE', 'SEARCH_ONLY'):
            return f"검색조건({','.join(self.pii_where_fields) or '-'})"
        if self.effective_pii_exposure is None:
            return f"노출필드 {self.pii_select_count}개 (건수미상)"
        return f"{self.effective_pii_exposure:,}건"
