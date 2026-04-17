"""DB 접근 로그 파서 - Oracle, MySQL, MSSQL 지원"""
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
        return (mysql_count / max(len(sample_lines), 1) > 0.1) or oracle_count >= 2 or mssql_count >= 2

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
