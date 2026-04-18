"""날짜/시간 유틸리티"""
from __future__ import annotations
from datetime import datetime, date, timedelta
import re


TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
    "%Y%m%d%H%M%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]


def parse_date_arg(date_str: str) -> date:
    """CLI 날짜 인수를 파싱합니다 (YYYY-MM-DD 형식)."""
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"날짜 형식이 잘못되었습니다. YYYY-MM-DD 형식으로 입력하세요: {date_str!r}")


def try_parse_timestamp(text: str, year_hint: int | None = None) -> datetime | None:
    """여러 형식을 시도하여 타임스탬프를 파싱합니다."""
    # 문자열에서 타임스탬프 후보 추출
    candidates = _extract_timestamp_candidates(text)

    for candidate in candidates:
        for fmt in TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(candidate, fmt)
                # syslog 형식처럼 연도 없는 경우 현재 연도 적용
                if dt.year == 1900 and year_hint:
                    dt = dt.replace(year=year_hint)
                elif dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt.replace(tzinfo=None)  # timezone-naive로 통일
            except ValueError:
                continue
    return None


def _extract_timestamp_candidates(text: str) -> list[str]:
    """텍스트에서 타임스탬프 후보 문자열을 추출합니다."""
    candidates = []

    # ISO 형식: 2024-01-15T14:23:01
    iso_matches = re.findall(
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z)?', text
    )
    candidates.extend(iso_matches)

    # Apache 형식: 15/Jan/2024:14:23:01 +0900
    apache_matches = re.findall(
        r'\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+\-]\d{4}', text
    )
    candidates.extend(apache_matches)

    # Syslog 형식: Jan 15 14:23:01
    syslog_matches = re.findall(
        r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        text, re.IGNORECASE
    )
    candidates.extend(syslog_matches)

    # 슬래시 날짜: 2024/01/15 14:23:01
    slash_matches = re.findall(r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}', text)
    candidates.extend(slash_matches)

    return candidates


def in_date_range(dt: datetime | None, start: date, end: date) -> bool:
    """datetime이 [start, end] 범위 내에 있는지 확인합니다."""
    if dt is None:
        return True  # 타임스탬프 없으면 포함 (파싱 실패 허용)
    d = dt.date()
    return start <= d <= end


def is_business_hours(dt: datetime, start_hour: int = 8, end_hour: int = 19) -> bool:
    """업무 시간 내인지 확인합니다."""
    if dt is None:
        return True
    return start_hour <= dt.hour < end_hour


def format_datetime(dt: datetime | None) -> str:
    if dt is None:
        return '알 수 없음'
    return dt.strftime('%Y-%m-%d %H:%M:%S')
