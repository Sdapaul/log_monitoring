"""
중앙 설정 파일 - 모든 임계값, 정규식 패턴, 로그 형식 시그니처를 관리합니다.
"""
from __future__ import annotations
import re
import json
from pathlib import Path

# ─────────────────────────────────────────────
# 개인정보 탐지 패턴 (한국 컨텍스트 기반)
# ─────────────────────────────────────────────
PII_PATTERNS: dict[str, tuple[str, str]] = {
    # 주민등록번호: YYMMDD-NNNNNNN (하이픈 선택)
    "RRN": (
        r"\b\d{6}[-\s]?[1-4]\d{6}\b",
        "CRITICAL"
    ),
    # 한국 전화번호: 010-XXXX-XXXX, 02-XXX-XXXX 등
    "PHONE": (
        r"\b0(?:1[016-9]|2|[3-9]\d)[-\s]?\d{3,4}[-\s]?\d{4}\b",
        "HIGH"
    ),
    # 계좌번호 (키워드 선행)
    "ACCOUNT_NO": (
        r"(?:계좌|account|acct|bankno|bank_no|account_no)[^\d]{0,15}(\d{10,14})",
        "CRITICAL"
    ),
    # 신용카드번호: 4x4 digit groups
    "CREDIT_CARD": (
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "CRITICAL"
    ),
    # 여권번호 (한국식)
    "PASSPORT": (
        r"\b[A-Z][A-Z0-9]\d{7}\b",
        "HIGH"
    ),
    # 이메일
    "EMAIL": (
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        "MEDIUM"
    ),
    # 쿼리 내 이름 (한국어)
    "NAME_IN_QUERY": (
        r"(?:name|이름|성명|고객명|cust_name|customer_name)\s*[=:'\"\s,]+([가-힣]{2,4})",
        "HIGH"
    ),
    # 한국 주소
    "ADDRESS": (
        r"[가-힣]{2,6}(?:시|도|군|구)\s*[가-힣]{2,6}(?:동|읍|면|로|길)\s*\d+",
        "MEDIUM"
    ),
    # 사원번호 (키워드 선행 필수)
    # 형태: 숫자만(12345678), 영문+숫자(EMP003, K-12345), 영문prefix+숫자(S00123)
    "EMP_ID_IN_QUERY": (
        r"(?:emp_id|사원번호|사번|employee_id|직원번호|empno|사원\s*id|staff_id|staff_no)"
        r"\s*[=:\s]\s*['\"]?"
        r"([A-Za-z]{0,4}[-]?\d{3,10})"
        r"['\"]?",
        "MEDIUM"
    ),
    # 생년월일
    "BIRTHDATE": (
        r"(?:birth|생년월일|dob|birthday)\s*[=:'\"\s]+(\d{4}[-./]\d{2}[-./]\d{2}|\d{8})",
        "HIGH"
    ),
    # IP 주소 (IPv4 + IPv6)
    # validate_ip()로 루프백/브로드캐스트 제외
    "IP_ADDRESS": (
        r"(?<!\d)"
        r"(?:"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)){3}"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
        r"|"
        r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
        r")"
        r"(?!\d)",
        "LOW"
    ),
}

# 컴파일된 패턴 (시작 시 1회만 컴파일)
COMPILED_PII: dict[str, tuple[re.Pattern, str]] = {
    name: (re.compile(pattern, re.IGNORECASE | re.UNICODE), severity)
    for name, (pattern, severity) in PII_PATTERNS.items()
}

# 빠른 사전 필터 키워드 (PII 패턴 실행 전 검사)
PII_TRIGGER_KEYWORDS: frozenset = frozenset([
    "select", "query", "insert", "update", "where",
    "name", "phone", "이름", "전화", "주민", "계좌",
    "주소", "address", "ssn", "rrn", "birth", "생년",
    "고객", "customer", "account", "acct", "card",
    "email", "passport", "여권", "사원번호", "empno",
    "cust", "member", "회원", "개인", "personal",
    "ip", "addr", "client", "remote", "src_ip", "접속",
    "사번", "staff", "empno", "emp_id", "employee",
])

# ─────────────────────────────────────────────
# 과다조회 임계값
# ─────────────────────────────────────────────
THRESHOLDS: dict = {
    # 고정 윈도우: 일별 쿼리 수
    "max_queries_per_day": 500,
    "critical_queries_per_day": 2000,

    # 슬라이딩 윈도우: 시간당 쿼리 수 (1시간 롤링)
    "max_queries_per_hour": 100,
    "critical_queries_per_hour": 500,

    # 야간/업무 외 시간 (24h, 현지 시간)
    "business_hours_start": 8,   # 08:00
    "business_hours_end": 19,    # 19:00
    "after_hours_threshold": 5,  # 업무 외 PII 조회 5건 초과 시 경고

    # 대량 조회 기준
    "bulk_select_row_threshold": 1000,  # LIMIT/rownum 이 이 값 초과 시
    "bulk_export_per_day": 3,           # 하루 3건 초과 시 경고

    # 고유 대상 다양성
    "unique_targets_per_day": 50,

    # ── 쿼리 결과 기반 개인정보 노출량 임계값 ─────────────────
    # 기간 내 실효 노출 총 건수 (결과건수 × PII필드수)
    "pii_exposure_medium":   1_000,   # MEDIUM 경고
    "pii_exposure_high":    10_000,   # HIGH 경고
    "pii_exposure_critical": 50_000,  # CRITICAL 경고 (즉각 조사)

    # 단일 쿼리 최대 노출 건수
    "pii_single_query_high":     5_000,
    "pii_single_query_critical": 20_000,

    # 위험 점수 가중치 (합계 100)
    # PII 접촉: 25 / 노출량(신규): 30 / 과다조회: 20 / 행동이상: 25
    "weight_pii_critical": 0.25,
    "weight_pii_high": 0.20,
    "weight_excessive_day": 0.20,
    "weight_excessive_hour": 0.15,
    "weight_after_hours": 0.05,
    "weight_bulk_export": 0.05,
}

# ─────────────────────────────────────────────
# 로그 형식 시그니처
# ─────────────────────────────────────────────
LOG_FORMAT_SIGNATURES: dict = {
    "syslog_rfc3164": {
        "pattern": r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+",
        "timestamp_fmt": "%b %d %H:%M:%S",
        "description": "Syslog RFC3164"
    },
    "syslog_rfc5424": {
        "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
        "timestamp_fmt": "%Y-%m-%dT%H:%M:%S",
        "description": "Syslog RFC5424"
    },
    "apache_combined": {
        "pattern": r'^\S+ \S+ \S+ \[[\w:/]+\s[+\-]\d{4}\] "',
        "timestamp_fmt": "%d/%b/%Y:%H:%M:%S %z",
        "description": "Apache/Nginx Combined Log"
    },
    "log4j_standard": {
        "pattern": r"^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}[,\.]\d{3}\s+(DEBUG|INFO|WARN|ERROR|FATAL)",
        "timestamp_fmt": "%Y-%m-%d %H:%M:%S",
        "description": "Log4j/Python logging"
    },
    "oracle_audit": {
        "pattern": r"(?:ACTION\s*:|DB USER\s*:|AUDIT\s+TYPE\s*:|SESSIONID\s*:)",
        "timestamp_fmt": None,
        "description": "Oracle Audit Trail"
    },
    "mysql_general": {
        "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+\d+\s+(?:Query|Connect|Quit|Init)",
        "timestamp_fmt": "%Y-%m-%dT%H:%M:%S.%fZ",
        "description": "MySQL General Query Log"
    },
    "mssql_audit": {
        "pattern": r"(?:LoginName|DatabaseName|ObjectName|StatementText).*,",
        "timestamp_fmt": "%Y-%m-%d %H:%M:%S",
        "description": "MSSQL Audit Log"
    },
    "postgresql": {
        "pattern": r"^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}.*(?:LOG|ERROR|WARNING|NOTICE|FATAL|PANIC):\s{1,3}(?:statement:|duration:|execute|AUDIT:)",
        "timestamp_fmt": "%Y-%m-%d %H:%M:%S",
        "description": "PostgreSQL Server Log"
    },
    "postgresql_csv": {
        "pattern": r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.\d]* \w+,"[^"]*","[^"]*","',
        "timestamp_fmt": "%Y-%m-%d %H:%M:%S",
        "description": "PostgreSQL CSV Log"
    },
    "csv_generic": {
        "pattern": r"^[^,\n]+,[^,\n]+,[^,\n]+,",
        "timestamp_fmt": None,
        "description": "CSV 형식"
    },
}

# 컴파일된 형식 시그니처
COMPILED_FORMAT_SIGNATURES: dict = {
    fmt: {**info, "compiled": re.compile(info["pattern"], re.IGNORECASE | re.MULTILINE)}
    for fmt, info in LOG_FORMAT_SIGNATURES.items()
}

# ─────────────────────────────────────────────
# 대량 조회 탐지 패턴
# ─────────────────────────────────────────────
BULK_EXPORT_PATTERNS: list[re.Pattern] = [
    re.compile(r'\bLIMIT\s+(\d+)', re.IGNORECASE),
    re.compile(r'\bROWNUM\s*<=?\s*(\d+)', re.IGNORECASE),
    re.compile(r'\bFETCH\s+FIRST\s+(\d+)\s+ROWS', re.IGNORECASE),
    re.compile(r'\bTOP\s+(\d+)\b', re.IGNORECASE),
]

# SELECT * 패턴 (WHERE 절 없이)
SELECT_STAR_NO_WHERE = re.compile(
    r'\bSELECT\s+\*\s+FROM\s+\w+\s*(?:;|$)',
    re.IGNORECASE
)


def load_threshold_overrides(path: str) -> None:
    """JSON 파일로부터 임계값을 오버라이드합니다."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            overrides = json.load(f)
        THRESHOLDS.update(overrides)
        print(f"[설정] 임계값 오버라이드 적용: {path}")
    except Exception as e:
        print(f"[경고] 임계값 파일 로드 실패: {e}")
