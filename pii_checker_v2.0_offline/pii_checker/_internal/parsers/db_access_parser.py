"""DB 접근 로그 파서 - Oracle, MySQL, MSSQL, PostgreSQL 지원"""
from __future__ import annotations
import re
import hashlib
from parsers.base_parser import BaseParser
from models.log_event import LogEvent
from utils.date_utils import try_parse_timestamp

# ── MySQL General Query Log ──────────────────────────────
# 2024-01-15T14:23:01.000000Z   12 Query  SELECT * FROM customers
MYSQL_GENERAL = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\d+)\s+(Query|Connect|Quit|Init DB|Field List)\s*(.*)',
    re.IGNORECASE
)
# Connect 이벤트: thread_id user@host on db
MYSQL_CONNECT = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\d+)\s+Connect\s+(\w+)@',
    re.IGNORECASE
)

# ── Oracle Audit Trail ───────────────────────────────────
# 멀티라인 블록
ORACLE_FIELDS = {
    'DB USER': re.compile(r'DB USER\s*:\s*"?([^"\n]+)"?', re.IGNORECASE),
    'ACTION': re.compile(r'\bACTION\s*:\s*"?([^"\n]+)"?', re.IGNORECASE),
    'OBJ NAME': re.compile(r'OBJ\s*NAME\s*:\s*"?([^"\n]+)"?', re.IGNORECASE),
    'TIMESTAMP': re.compile(r'TIMESTAMP\s*:\s*([^\n]+)', re.IGNORECASE),
    'SQL TEXT': re.compile(r'SQL TEXT\s*:\s*([^\n]+(?:\n\s+[^\n]+)*)', re.IGNORECASE),
    'RETURNCODE': re.compile(r'RETURNCODE\s*:\s*(\d+)', re.IGNORECASE),
    'SESSIONID': re.compile(r'SESSIONID\s*:\s*(\d+)', re.IGNORECASE),
    'OS USERNAME': re.compile(r'OS USERNAME\s*:\s*"?([^"\n]+)"?', re.IGNORECASE),
}
ORACLE_RECORD_START = re.compile(r'^(?:AUDIT TRAIL|ACTION\s*:|DB USER\s*:|Audit record)', re.IGNORECASE)

# ── MSSQL Audit Log ─────────────────────────────────────
# LoginName, DatabaseName, ObjectName, StatementText 필드 포함
MSSQL_PATTERN = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})[^\n]*?'
    r'(?:LoginName|login_name|사용자)[^\n:]*[:\s]+(\w+)[^\n]*\n?'
    r'(?:[^\n]*(?:Statement|StatementText|SQL)[^\n:]*[:\s]+([^\n]+))?',
    re.IGNORECASE | re.MULTILINE
)

# ── PostgreSQL Server Log ────────────────────────────────
# 표준: 2024-01-15 14:23:01.123 UTC [12345] user@db LOG:  statement: SELECT ...
# 축약: 2024-01-15 14:23:01 LOG:  statement: SELECT ...
PG_STANDARD = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+UTC|\s+[+-]\d{2}:?\d{2})?)'
    r'(?:[^[]*\[(\d+)\])?'           # optional [pid]
    r'(?:[^@]*?(\w[\w.]+)@(\w+))?'  # optional user@db
    r'\s+(?:LOG|ERROR|WARNING|NOTICE|FATAL|PANIC|DEBUG|INFO):\s+(.*)',
    re.IGNORECASE | re.DOTALL
)
# CSV 형식: timestamp,user,db,app,client,...,"message"
PG_CSV = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s*\w*),'
    r'"([^"]*)",'   # user
    r'"([^"]*)",'   # db
    r'"[^"]*",'     # app
    r'"([^"]*)"',   # client_addr
    re.IGNORECASE
)
# message 열 (CSV 마지막 의미 있는 필드)
PG_CSV_MSG = re.compile(r'(?:^|,)"((?:statement|execute|duration|AUDIT)[^"]*)"', re.IGNORECASE)

# SQL 문 추출 (statement:/execute .:/query:)
PG_STMT_RE  = re.compile(r'(?:statement|execute(?:\s+\S+)?|query):\s+(.*)', re.IGNORECASE | re.DOTALL)
PG_DURATION_RE = re.compile(
    r'duration:\s+[\d.]+\s+ms\s+(?:statement|execute(?:\s+\S+)?):\s+(.*)',
    re.IGNORECASE | re.DOTALL
)
# pgaudit: AUDIT: SESSION,1,1,READ,SELECT,,,"SELECT ..."
PG_AUDIT_RE = re.compile(
    r'AUDIT:\s+\w+,\d+,\d+,(\w+),(\w+),+,"([^"]*)"',
    re.IGNORECASE
)

def _is_pg_line(line: str) -> bool:
    """PostgreSQL 로그 라인 빠른 판별."""
    return bool(PG_STANDARD.match(line))

# ── 공통 SQL 패턴 ────────────────────────────────────────
TABLE_NAME_PATTERN = re.compile(
    r'\bFROM\s+([`"]?[\w.]+[`"]?)|\bJOIN\s+([`"]?[\w.]+[`"]?)|\bINTO\s+([`"]?[\w.]+[`"]?)',
    re.IGNORECASE
)
LIMIT_PATTERN = re.compile(r'\bLIMIT\s+(\d+)|\bROWNUM\s*<=?\s*(\d+)|\bTOP\s+(\d+)', re.IGNORECASE)


def extract_table_name(sql: str) -> str | None:
    m = TABLE_NAME_PATTERN.search(sql)
    if m:
        return next((g for g in m.groups() if g), None)
    return None


def query_fingerprint(sql: str) -> str:
    """SQL 리터럴을 제거하고 쿼리 지문을 생성합니다."""
    normalized = re.sub(r"'[^']*'", "?", sql)
    normalized = re.sub(r'\b\d+\b', '?', normalized)
    normalized = re.sub(r'\s+', ' ', normalized).strip().upper()
    return hashlib.md5(normalized.encode()).hexdigest()[:12]


class DbAccessParser(BaseParser):
    log_type = 'db'

    def __init__(self):
        # MySQL: thread_id -> user_id 매핑
        self._thread_user_map: dict[str, str] = {}
        # 쿼리 지문 추적 (대량 페이지네이션 감지)
        self._query_fingerprints: dict[str, list] = {}

    def can_parse(self, sample_lines: list[str]) -> bool:
        full_text = '\n'.join(sample_lines)
        mysql_count = sum(1 for line in sample_lines if MYSQL_GENERAL.match(line))
        oracle_count = sum(1 for f in ORACLE_FIELDS.values() if f.search(full_text))
        mssql_count = len(re.findall(r'(?:LoginName|StatementText|DatabaseName)', full_text, re.IGNORECASE))
        pg_count = sum(1 for line in sample_lines if _is_pg_line(line))
        return (
            (mysql_count / max(len(sample_lines), 1) > 0.1)
            or oracle_count >= 2
            or mssql_count >= 2
            or (pg_count / max(len(sample_lines), 1) > 0.1)
        )

    def parse_line(self, line: str, line_no: int, source_file: str, context: dict) -> LogEvent | None:
        if not line.strip():
            return None

        # MySQL 연결 이벤트 - thread_id -> user 매핑
        m = MYSQL_CONNECT.match(line)
        if m:
            self._thread_user_map[m.group(2)] = m.group(3)
            return None  # 연결 이벤트는 분석 대상 아님

        # MySQL 일반 쿼리
        m = MYSQL_GENERAL.match(line)
        if m:
            return self._parse_mysql_line(m, line, line_no, source_file)

        # Oracle 멀티라인 블록 (context에 누적된 경우)
        if context.get('oracle_block'):
            block = context['oracle_block']
            block.append(line)
            if ORACLE_FIELDS['RETURNCODE'].search(line):
                # 블록 완성
                record = '\n'.join(block)
                context['oracle_block'] = []
                context['oracle_start_line'] = line_no
                return self._parse_oracle_block(record, context.get('oracle_start_line', line_no), source_file)
            return None

        if ORACLE_RECORD_START.match(line):
            context['oracle_block'] = [line]
            context['oracle_start_line'] = line_no
            return None

        # PostgreSQL 표준/CSV 로그
        m = PG_STANDARD.match(line)
        if m:
            return self._parse_pg_line(m, line, line_no, source_file)

        # MSSQL 또는 일반 DB 로그 폴백
        return self._parse_generic_db_line(line, line_no, source_file)

    def _parse_mysql_line(self, m, line: str, line_no: int, source_file: str) -> LogEvent:
        ts = try_parse_timestamp(m.group(1))
        thread_id = m.group(2)
        query_type = m.group(3)
        sql_text = m.group(4).strip()

        user_id = self._thread_user_map.get(thread_id) or self.extract_user_id(sql_text)
        table = extract_table_name(sql_text)

        # 대량 조회 감지
        is_bulk = self._check_bulk(sql_text, ts)

        return self.make_event(
            raw_line=line,
            source_file=source_file,
            line_no=line_no,
            timestamp=ts,
            user_id=user_id,
            ip_address=self.extract_ip(line),
            action=query_type.upper(),
            target=table,
            query_text=sql_text,
            extra={'thread_id': thread_id, 'is_bulk': is_bulk, 'db_type': 'mysql'},
        )

    def _parse_oracle_block(self, block_text: str, line_no: int, source_file: str) -> LogEvent:
        def extract_field(field_pattern):
            m = field_pattern.search(block_text)
            return m.group(1).strip() if m else None

        user_id = extract_field(ORACLE_FIELDS['DB USER'])
        os_user = extract_field(ORACLE_FIELDS['OS USERNAME'])
        action = extract_field(ORACLE_FIELDS['ACTION'])
        obj_name = extract_field(ORACLE_FIELDS['OBJ NAME'])
        ts_str = extract_field(ORACLE_FIELDS['TIMESTAMP'])
        sql_text = extract_field(ORACLE_FIELDS['SQL TEXT']) or block_text

        ts = try_parse_timestamp(ts_str) if ts_str else None
        is_bulk = self._check_bulk(sql_text, ts)

        return self.make_event(
            raw_line=block_text[:500],  # 처음 500자만 저장
            source_file=source_file,
            line_no=line_no,
            timestamp=ts,
            user_id=user_id or os_user,
            action=action,
            target=obj_name,
            query_text=sql_text,
            extra={'os_user': os_user, 'is_bulk': is_bulk, 'db_type': 'oracle'},
        )

    def _parse_pg_line(self, m, line: str, line_no: int, source_file: str) -> LogEvent:
        ts   = try_parse_timestamp(m.group(1))
        pid  = m.group(2)
        user = m.group(3)
        db   = m.group(4)
        msg  = (m.group(5) or '').strip()

        # SQL 추출 (duration: ... statement: ... 또는 statement: ...)
        sql_text = None
        dm = PG_DURATION_RE.match(msg)
        if dm:
            sql_text = dm.group(1).strip()
        else:
            sm = PG_STMT_RE.match(msg)
            if sm:
                sql_text = sm.group(1).strip()

        # pgaudit 파싱
        am = PG_AUDIT_RE.search(msg)
        if am and not sql_text:
            sql_text = am.group(3).strip()

        if not sql_text:
            sql_text = msg  # 비정형 메시지도 PII 스캔 대상으로 유지

        table = extract_table_name(sql_text) if sql_text else None
        is_bulk = self._check_bulk(sql_text, ts) if sql_text else False

        return self.make_event(
            raw_line=line,
            source_file=source_file,
            line_no=line_no,
            timestamp=ts,
            user_id=user or self.extract_user_id(line),
            ip_address=self.extract_ip(line),
            action=self.extract_action(sql_text or line),
            target=db or table,
            query_text=sql_text,
            extra={'pid': pid, 'pg_db': db, 'is_bulk': is_bulk, 'db_type': 'postgresql'},
        )

    def _parse_pg_csv_line(self, line: str, line_no: int, source_file: str) -> LogEvent | None:
        m = PG_CSV.match(line)
        if not m:
            return None
        ts      = try_parse_timestamp(m.group(1))
        user    = m.group(2)
        db      = m.group(3)
        client  = m.group(4)

        msg_m = PG_CSV_MSG.search(line)
        msg   = msg_m.group(1) if msg_m else line

        sm = PG_STMT_RE.match(msg)
        sql_text = sm.group(1).strip() if sm else msg

        table   = extract_table_name(sql_text)
        is_bulk = self._check_bulk(sql_text, ts)

        return self.make_event(
            raw_line=line[:500],
            source_file=source_file,
            line_no=line_no,
            timestamp=ts,
            user_id=user,
            ip_address=client,
            action=self.extract_action(sql_text),
            target=db or table,
            query_text=sql_text,
            extra={'pg_db': db, 'is_bulk': is_bulk, 'db_type': 'postgresql'},
        )

    def _parse_generic_db_line(self, line: str, line_no: int, source_file: str) -> LogEvent:
        ts = try_parse_timestamp(line)
        user_id = self.extract_user_id(line)
        action = self.extract_action(line)
        table = extract_table_name(line)
        is_bulk = self._check_bulk(line, ts)

        return self.make_event(
            raw_line=line,
            source_file=source_file,
            line_no=line_no,
            timestamp=ts,
            user_id=user_id,
            ip_address=self.extract_ip(line),
            action=action,
            target=table,
            query_text=line,
            extra={'is_bulk': is_bulk, 'db_type': 'generic'},
        )

    def _check_bulk(self, sql: str, ts) -> bool:
        """대량 조회 여부를 판단합니다."""
        from config import THRESHOLDS, BULK_EXPORT_PATTERNS, SELECT_STAR_NO_WHERE
        for pattern in BULK_EXPORT_PATTERNS:
            m = pattern.search(sql)
            if m:
                # 첫 번째 캡처 그룹에서 숫자 추출
                for group in m.groups():
                    if group and int(group) >= THRESHOLDS['bulk_select_row_threshold']:
                        return True
        if SELECT_STAR_NO_WHERE.search(sql):
            return True
        return False
