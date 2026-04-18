"""
SQL 절 분석기 - 쿼리 결과 기반 개인정보 노출량 계산
- SELECT 절의 PII 컬럼 탐지 (실제 노출)
- WHERE 절 PII (검색 조건, 상대적으로 낮은 위험)
- 쿼리 결과 건수 파싱 (로그 패턴)
- 실효 노출량 = 결과 건수 × PII 컬럼 수
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

# ── 결과 건수 파싱 패턴 ────────────────────────────────────
RESULT_ROW_PATTERNS: list[re.Pattern] = [
    # MySQL slow query log: Rows_sent: 1847
    re.compile(r'Rows_sent\s*:\s*(\d+)', re.IGNORECASE),
    # Oracle audit: ROWS_PROCESSED : 1847
    re.compile(r'ROWS[\s_]PROCESSED\s*:\s*(\d+)', re.IGNORECASE),
    # MSSQL: RowsAffected=1847
    re.compile(r'Rows(?:Affected|Count)\s*[=:]\s*(\d+)', re.IGNORECASE),
    # 한국어 앱 로그: 1,847건 반환 / 반환: 1847건 / 조회결과 1847건
    re.compile(r'([\d,]+)\s*건\s*(?:반환|조회|검색|출력)', re.IGNORECASE),
    re.compile(r'(?:반환|조회결과|결과)\s*:?\s*([\d,]+)\s*건', re.IGNORECASE),
    # 영어 앱 로그: returned 1847 rows / 1847 rows returned
    re.compile(r'returned\s+([\d,]+)\s+rows?', re.IGNORECASE),
    re.compile(r'([\d,]+)\s+rows?\s+(?:returned|sent|affected|fetched)', re.IGNORECASE),
    # ORM/MyBatis: <selectList> returned 1847 results
    re.compile(r'(?:selectList|executeQuery|findAll)\D{0,30}([\d,]+)\s*results?', re.IGNORECASE),
    # totalCount: 1847 / resultCount=1847
    re.compile(r'(?:total|result)(?:Count|Size|Rows)\s*[=:]\s*([\d,]+)', re.IGNORECASE),
    # fetchSize: 1847
    re.compile(r'fetch(?:Size|Count)\s*[=:]\s*([\d,]+)', re.IGNORECASE),
    # MySQL CLI: 1847 rows in set
    re.compile(r'([\d,]+)\s+rows?\s+in\s+set', re.IGNORECASE),
    # PostgreSQL: rows=1847
    re.compile(r'\brows\s*=\s*([\d,]+)', re.IGNORECASE),
    # PostgreSQL pgaudit / 일반: Rows Affected: 1847
    re.compile(r'rows?\s+affected\s*[=:]\s*([\d,]+)', re.IGNORECASE),
]

# ── PII 컬럼명 키워드 (SELECT 절) ─────────────────────────
PII_COLUMN_KEYWORDS: frozenset = frozenset([
    # 주민등록번호
    "주민번호", "주민등록번호", "rrn", "ssn", "resident", "jumin", "rno",
    # 이름
    "이름", "성명", "고객명", "cust_name", "customer_name", "name", "성함", "nm",
    # 전화번호
    "전화", "전화번호", "phone", "mobile", "tel", "휴대폰", "휴대전화", "cellphone",
    "hp_no", "cell_no", "phone_no", "tel_no",
    # 주소
    "주소", "address", "addr", "거주지", "home_addr", "road_addr",
    # 이메일
    "email", "이메일", "mail", "e_mail",
    # 계좌/카드
    "계좌", "계좌번호", "account_no", "bankno", "bank_no",
    "card", "카드번호", "신용카드", "card_no", "credit",
    # 생년월일
    "생년월일", "생년", "birthday", "birth_date", "birthdate", "dob", "birth",
    # 여권
    "여권", "여권번호", "passport",
    # 사원번호
    "사원번호", "emp_id", "employee_id", "empno",
])

# SELECT * 관련
SELECT_STAR_RE = re.compile(r'\bSELECT\s+\*', re.IGNORECASE)
SELECT_TABLE_STAR_RE = re.compile(r'\bSELECT\s+\w+\.\*', re.IGNORECASE)

# SQL 절 추출
SELECT_LIST_RE = re.compile(
    r'\bSELECT\s+(.*?)\bFROM\b',
    re.IGNORECASE | re.DOTALL
)
WHERE_CLAUSE_RE = re.compile(
    r'\bWHERE\b(.*?)(?:\bGROUP\s+BY\b|\bORDER\s+BY\b|\bHAVING\b|\bLIMIT\b|;|$)',
    re.IGNORECASE | re.DOTALL
)

# 민감 테이블명 (SELECT * FROM 시 자동 고위험 처리)
SENSITIVE_TABLE_KEYWORDS: frozenset = frozenset([
    "customers", "members", "personal_info", "personal",
    "고객", "회원", "개인정보", "cust", "member",
    "employee", "사원", "직원", "accounts", "user_info",
])


@dataclass
class SqlAnalysis:
    """SQL 분석 결과"""
    select_pii_fields: list[str] = field(default_factory=list)  # SELECT절 PII 컬럼명
    where_pii_fields: list[str] = field(default_factory=list)   # WHERE절 PII 컬럼명
    is_select_star: bool = False       # SELECT * 여부
    is_sensitive_table: bool = False   # 민감 테이블 대상 여부
    result_row_count: int | None = None  # 결과 건수 (None=알 수 없음)
    effective_exposure: int | None = None  # 실효 노출량
    exposure_type: str = 'UNKNOWN'  # 'FULL_EXPOSURE'|'PARTIAL_EXPOSURE'|'SEARCH_ONLY'|'NONE'

    @property
    def pii_select_count(self) -> int:
        """SELECT절 PII 필드 수 (SELECT *는 기본값 5 사용)"""
        if self.is_select_star and self.is_sensitive_table:
            return 5  # 민감 테이블 SELECT * → 5개 PII 필드 가정
        if self.is_select_star:
            return 3  # 일반 SELECT * → 3개 가정
        return len(self.select_pii_fields)

    @property
    def exposure_summary(self) -> str:
        if self.effective_exposure is None:
            return f"노출 필드 {self.pii_select_count}개 (건수 미상)"
        return f"노출 필드 {self.pii_select_count}개 × {self.result_row_count:,}건 = {self.effective_exposure:,}건"


def extract_result_row_count(text: str) -> int | None:
    """
    로그 텍스트에서 쿼리 결과 건수를 추출합니다.
    찾지 못하면 None 반환 (0과 구별).
    """
    for pattern in RESULT_ROW_PATTERNS:
        m = pattern.search(text)
        if m:
            try:
                val = int(m.group(1).replace(',', ''))
                if val >= 0:
                    return val
            except (ValueError, IndexError):
                continue
    return None


def split_select_where(sql: str) -> tuple[str, str]:
    """
    SQL을 SELECT 목록과 WHERE 절로 분리합니다.
    Returns: (select_list_text, where_clause_text)
    SELECT 문이 아니면 ('', '') 반환.
    """
    if not sql or not re.search(r'\bSELECT\b', sql, re.IGNORECASE):
        return '', ''

    select_list = ''
    where_clause = ''

    # SELECT 목록 추출 (중첩 괄호 처리)
    try:
        m = SELECT_LIST_RE.search(sql)
        if m:
            raw = m.group(1)
            # 최상위 레벨만 (서브쿼리 내부 제외)
            depth = 0
            buf = []
            for ch in raw:
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                if depth == 0:
                    buf.append(ch)
            select_list = ''.join(buf).strip()
    except Exception:
        pass

    # WHERE 절 추출
    try:
        m = WHERE_CLAUSE_RE.search(sql)
        if m:
            where_clause = m.group(1).strip()
    except Exception:
        pass

    return select_list, where_clause


def count_pii_select_fields(select_list: str) -> list[str]:
    """
    SELECT 절 컬럼 목록에서 PII 컬럼명을 찾아 반환합니다.
    """
    if not select_list:
        return []

    found = []
    # 컬럼 목록을 쉼표로 분리
    cols = select_list.split(',')
    for col in cols:
        # 별칭 제거: "table.column AS alias" → "column"
        col_clean = re.sub(r'\bAS\s+\w+', '', col, flags=re.IGNORECASE)
        # 테이블 접두사 제거: "t.name" → "name"
        parts = col_clean.strip().split('.')
        col_name = parts[-1].strip().lower().strip('`"\' ')

        for keyword in PII_COLUMN_KEYWORDS:
            if keyword in col_name:
                found.append(col_name)
                break

    return found


def check_sensitive_table(sql: str) -> bool:
    """SQL 대상 테이블이 민감 테이블인지 확인합니다."""
    from_match = re.search(r'\bFROM\s+([\w,\s`"\']+?)(?:\bWHERE\b|\bJOIN\b|\bORDER\b|$)',
                           sql, re.IGNORECASE)
    if not from_match:
        return False
    table_text = from_match.group(1).lower()
    return any(kw in table_text for kw in SENSITIVE_TABLE_KEYWORDS)


def analyze_sql(sql: str, context_text: str = '') -> SqlAnalysis:
    """
    SQL 전체를 분석하여 SqlAnalysis 결과를 반환합니다.
    context_text: SQL 주변 로그 텍스트 (결과 건수 추출용)
    """
    if not sql:
        return SqlAnalysis(exposure_type='NONE')

    result = SqlAnalysis()

    # SELECT * 여부
    result.is_select_star = bool(
        SELECT_STAR_RE.search(sql) or SELECT_TABLE_STAR_RE.search(sql)
    )

    # 민감 테이블 여부
    result.is_sensitive_table = check_sensitive_table(sql)

    # SELECT/WHERE 분리
    select_list, where_text = split_select_where(sql)

    # SELECT 절 PII 필드
    if not result.is_select_star:
        result.select_pii_fields = count_pii_select_fields(select_list)

    # WHERE 절 PII 필드
    if where_text:
        result.where_pii_fields = count_pii_select_fields(where_text)

    # 노출 유형 결정
    if not re.search(r'\bSELECT\b', sql, re.IGNORECASE):
        result.exposure_type = 'NONE'
    elif result.pii_select_count > 0:
        result.exposure_type = 'FULL_EXPOSURE' if result.is_select_star else 'PARTIAL_EXPOSURE'
    elif result.where_pii_fields:
        result.exposure_type = 'SEARCH_ONLY'
    else:
        result.exposure_type = 'NONE'

    # 결과 건수 추출 (SQL + 주변 로그)
    search_text = (context_text or '') + ' ' + sql
    result.result_row_count = extract_result_row_count(search_text)

    # 실효 노출량 계산
    pii_count = result.pii_select_count
    if result.result_row_count is not None and pii_count > 0:
        result.effective_exposure = result.result_row_count * pii_count
    else:
        result.effective_exposure = None  # 미상

    return result
