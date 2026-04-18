"""파서 추상 기반 클래스"""
from __future__ import annotations
import re
from abc import ABC, abstractmethod
from models.log_event import LogEvent

# 사용자 ID 추출 공통 패턴
USER_ID_PATTERNS: list[re.Pattern] = [
    re.compile(r'\buser(?:id|name)?[=:\s]+[\'"]?(\w[\w.\-@]{1,30})[\'"]?', re.IGNORECASE),
    re.compile(r'\bemployee[_\-]?(?:id|no)?[=:\s]+[\'"]?(\w{3,15})[\'"]?', re.IGNORECASE),
    re.compile(r'\bemp(?:no|_?id)?[=:\s]+[\'"]?(\w{3,15})[\'"]?', re.IGNORECASE),
    re.compile(r'\b사원번호[=:\s]+([\w\d]{3,15})', re.IGNORECASE),
    re.compile(r'\bDB USER\s*:\s*(\w+)', re.IGNORECASE),
    re.compile(r'\bloginid[=:\s]+[\'"]?(\w[\w.\-]{1,30})[\'"]?', re.IGNORECASE),
    re.compile(r'\baccount[=:\s]+[\'"]?(\w[\w.\-@]{1,30})[\'"]?', re.IGNORECASE),
    re.compile(r'\[(\w{3,20})\].*(?:query|select|access)', re.IGNORECASE),
]

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

ACTION_PATTERN = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC|CALL|GET|POST|PUT|DELETE|PATCH|LOGIN|LOGOUT|QUERY)\b',
    re.IGNORECASE
)


class BaseParser(ABC):
    log_type: str = 'unknown'

    @abstractmethod
    def can_parse(self, sample_lines: list[str]) -> bool:
        """이 파서가 해당 형식을 처리할 수 있는지 반환합니다."""

    @abstractmethod
    def parse_line(self, line: str, line_no: int, source_file: str, context: dict) -> LogEvent | None:
        """
        한 줄을 파싱합니다.
        None을 반환하면 건너뜁니다 (주석, 헤더, 빈 줄 등).
        context: 파서 간 상태 공유 딕셔너리 (멀티라인 레코드용)
        """

    def extract_user_id(self, text: str) -> str | None:
        """공통 사용자 ID 추출 로직"""
        for pattern in USER_ID_PATTERNS:
            m = pattern.search(text)
            if m:
                val = m.group(1).strip("'\"")
                # 너무 짧거나 일반적인 값 제외
                if len(val) >= 2 and val.lower() not in ('none', 'null', 'na', 'n/a', '-'):
                    return val
        return None

    def extract_ip(self, text: str) -> str | None:
        m = IP_PATTERN.search(text)
        return m.group(0) if m else None

    def extract_action(self, text: str) -> str | None:
        m = ACTION_PATTERN.search(text)
        return m.group(1).upper() if m else None

    def make_event(
        self, raw_line: str, source_file: str, line_no: int,
        timestamp=None, user_id=None, ip_address=None,
        action=None, target=None, query_text=None, extra=None
    ) -> LogEvent:
        return LogEvent(
            raw_line=raw_line,
            source_file=source_file,
            line_no=line_no,
            timestamp=timestamp,
            user_id=user_id,
            ip_address=ip_address,
            action=action,
            target=target,
            query_text=query_text or raw_line,
            log_type=self.log_type,
            extra=extra or {},
        )
