"""
추가 샘플 로그 생성기 - PostgreSQL, Oracle, MSSQL, 비정형, 한글숫자 형식
생성 파일:
  sample_logs/postgresql.log
  sample_logs/oracle_audit.log
  sample_logs/mssql_audit.log
  sample_logs/unstructured.txt
  sample_logs/korean_digits.log
날짜 범위: 2024-03-01 ~ 2024-03-31
유효 주민번호: 체크섬 검증 통과 값 사용
유효 카드번호: Luhn 검증 통과 값 사용 (4111-1111-1111-1111)
"""
import os
import random
from datetime import datetime, timedelta

OUT_DIR = os.path.join(os.path.dirname(__file__), 'sample_logs')
os.makedirs(OUT_DIR, exist_ok=True)

# ── 고정 상수 ──────────────────────────────────────────────
START_DATE = datetime(2024, 3, 1, 0, 0, 0)
END_DATE   = datetime(2024, 3, 31, 23, 59, 59)

# 체크섬 검증 통과 주민번호
VALID_RRNS = [
    '800101-1000008',
    '900315-2100001',
    '850601-1987650',
    '951225-2100002',
    '780920-1123450',
]

# Luhn 통과 카드번호
VALID_CARDS = [
    '4111-1111-1111-1111',
    '4532-0151-1283-0366',
    '4916-3384-2042-7894',
]

# 사용자 풀
USERS = {
    'normal': ['user101', 'user102', 'user103', 'user104', 'user105',
               'user201', 'user202', 'user203'],
    'suspect_excess': ['emp003'],   # 과다조회 의심
    'suspect_night':  ['emp007'],   # 야간 PII 조회
    'suspect_bulk':   ['admin01'],  # 대량 조회
}
ALL_USERS = (USERS['normal'] + USERS['suspect_excess'] +
             USERS['suspect_night'] + USERS['suspect_bulk'])

TABLES = ['customers', 'members', 'personal_info', 'accounts', 'orders']
PII_TABLES = ['customers', 'members', 'personal_info']

NORMAL_QUERIES = [
    "SELECT order_id, product_id, qty FROM orders WHERE order_date > '2024-03-01'",
    "SELECT COUNT(*) FROM orders GROUP BY status",
    "UPDATE orders SET status='shipped' WHERE order_id=12345",
    "SELECT product_name, price FROM products WHERE category='electronics'",
    "INSERT INTO audit_log(user_id, action) VALUES('user101', 'login')",
    "SELECT id, created_at FROM sessions WHERE expires_at < NOW()",
]

PII_QUERIES = [
    "SELECT name, phone, rrn FROM customers WHERE cust_id={}",
    "SELECT cust_name, email, address FROM members WHERE member_id={}",
    "SELECT * FROM personal_info WHERE dept_id={}",
    "SELECT name, birthday, phone FROM customers WHERE branch_id={}",
    "SELECT account_no, card_no, name FROM accounts WHERE user_id={}",
]

BULK_QUERIES = [
    "SELECT name, phone, rrn, email, address FROM customers WHERE created_date >= '2024-03-01'",
    "SELECT * FROM members WHERE status='active'",
    "SELECT cust_name, rrn, phone, card_no FROM customers WHERE dept='영업부'",
    "SELECT * FROM personal_info WHERE hire_date >= '2020-01-01'",
]


def rand_dt(start=START_DATE, end=END_DATE):
    delta = int((end - start).total_seconds())
    return start + timedelta(seconds=random.randint(0, delta))


def night_dt():
    """22:00 ~ 05:59 사이 타임스탬프."""
    day = START_DATE + timedelta(days=random.randint(0, 30))
    hour = random.choice(list(range(22, 24)) + list(range(0, 6)))
    return day.replace(hour=hour, minute=random.randint(0, 59),
                       second=random.randint(0, 59))


def business_dt():
    """09:00 ~ 18:00 사이 타임스탬프."""
    day = START_DATE + timedelta(days=random.randint(0, 30))
    return day.replace(hour=random.randint(9, 17), minute=random.randint(0, 59),
                       second=random.randint(0, 59))


# ── 1. PostgreSQL 로그 ─────────────────────────────────────

def make_postgresql_log():
    lines = []

    def pg_line(dt, user, db, pid, msg):
        ts = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ' UTC'
        return f"{ts} [{pid}] {user}@{db} LOG:  {msg}"

    def pg_stmt(dt, user, db, pid, sql, rows=None):
        result = []
        ms = random.randint(1, 500)
        result.append(pg_line(dt, user, db, pid,
                               f"duration: {ms}.{random.randint(100,999)} ms  statement: {sql}"))
        if rows is not None:
            result.append(pg_line(dt, user, db, pid,
                                   f"rows={rows}"))
        return result

    pid_base = 10000

    # 정상 로그 (일반 사용자)
    for _ in range(300):
        u = random.choice(USERS['normal'])
        dt = business_dt()
        pid = pid_base + random.randint(0, 500)
        sql = random.choice(NORMAL_QUERIES)
        lines.extend(pg_stmt(dt, u, 'appdb', pid, sql))

    # emp003: 과다조회 (하루에 쿼리 집중)
    burst_day = datetime(2024, 3, 14, 9, 0, 0)
    for i in range(180):
        dt = burst_day + timedelta(minutes=i // 3, seconds=(i % 3) * 20)
        pid = pid_base + 700
        cid = random.randint(1000, 9999)
        sql = random.choice(PII_QUERIES).format(cid)
        rows = random.randint(1, 5)
        lines.extend(pg_stmt(dt, 'emp003', 'custdb', pid, sql, rows))

    # emp007: 야간 PII 조회
    for _ in range(40):
        dt = night_dt()
        pid = pid_base + 800
        cid = random.randint(1000, 9999)
        sql = random.choice(PII_QUERIES).format(cid)
        rows = random.randint(1, 10)
        lines.extend(pg_stmt(dt, 'emp007', 'custdb', pid, sql, rows))

    # admin01: 대량 조회 (BULK_EXPORT)
    for _ in range(15):
        dt = business_dt()
        pid = pid_base + 900
        sql = random.choice(BULK_QUERIES)
        rows = random.randint(500, 5000)
        lines.extend(pg_stmt(dt, 'admin01', 'custdb', pid, sql, rows))

    # pgaudit 스타일 감사 로그
    for _ in range(50):
        u = random.choice(ALL_USERS)
        dt = rand_dt()
        pid = pid_base + random.randint(0, 999)
        cid = random.randint(1000, 9999)
        sql = random.choice(PII_QUERIES).format(cid)
        lines.append(pg_line(dt, u, 'custdb', pid,
                              f"AUDIT: SESSION,1,1,READ,SELECT,,{sql},<none>"))

    # 에러 로그
    for _ in range(20):
        dt = rand_dt()
        pid = pid_base + random.randint(0, 200)
        lines.append(
            f"{dt.strftime('%Y-%m-%d %H:%M:%S.000 UTC')} [{pid}] postgres@appdb "
            f"ERROR:  relation \"unknown_table\" does not exist"
        )

    lines.sort()
    path = os.path.join(OUT_DIR, 'postgresql.log')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"생성: {path} ({len(lines)}줄)")


# ── 2. Oracle Audit 로그 ──────────────────────────────────

def make_oracle_audit_log():
    blocks = []

    def oracle_block(dt, user, sql, rows=None, priv=None):
        ts = dt.strftime('%a %b %d %H:%M:%S %Y')
        action_no = random.randint(3, 104)
        priv = priv or 'CREATE SESSION'
        r = rows if rows is not None else random.randint(0, 10)
        block = (
            f"\n"
            f"Audit file /u01/app/oracle/admin/ORCL/adump/orcl_ora_{random.randint(10000,99999)}_1.aud\n"
            f"Oracle Database 19c Enterprise Edition Release 19.0.0.0.0\n"
            f"Build label: RDBMS_19.3.0.0.0\n"
            f"\n"
            f"SESSIONID        : {random.randint(100000, 999999)}\n"
            f"ENTRYID          : 1\n"
            f"STATEMENT        : {random.randint(1, 9999)}\n"
            f"TIMESTAMP        : {ts}\n"
            f"USERID           : {user}\n"
            f"USERHOST         : DBSERVER01\n"
            f"TERMINAL         : pts/0\n"
            f"ACTION#          : {action_no}\n"
            f"ACTION           : {sql}\n"
            f"RETURNCODE       : 0\n"
            f"PRIVILEGE        : {priv}\n"
            f"ROWS_PROCESSED   : {r}\n"
            f"OBJ$NAME         : CUSTOMERS\n"
            f"OS_USERNAME      : oracle\n"
        )
        return block

    # 정상 쿼리
    for _ in range(120):
        u = random.choice(USERS['normal'])
        dt = business_dt()
        sql = random.choice(NORMAL_QUERIES)
        blocks.append(oracle_block(dt, u.upper(), sql))

    # emp003: 과다조회
    burst_day = datetime(2024, 3, 21, 10, 0, 0)
    for i in range(150):
        dt = burst_day + timedelta(minutes=i // 2, seconds=(i % 2) * 30)
        cid = random.randint(10000, 99999)
        sql = f"SELECT NAME, PHONE, RRN, EMAIL FROM CUSTOMERS WHERE CUST_ID={cid}"
        blocks.append(oracle_block(dt, 'EMP003', sql, rows=random.randint(1, 3)))

    # emp007: 야간 PII
    for _ in range(35):
        dt = night_dt()
        cid = random.randint(10000, 99999)
        sql = f"SELECT NAME, RRN, ADDRESS, PHONE FROM MEMBERS WHERE ID={cid}"
        blocks.append(oracle_block(dt, 'EMP007', sql, rows=random.randint(1, 5)))

    # admin01: 대량 조회
    for _ in range(10):
        dt = business_dt()
        sql = random.choice(BULK_QUERIES).upper()
        blocks.append(oracle_block(dt, 'ADMIN01', sql,
                                    rows=random.randint(1000, 10000),
                                    priv='SELECT ANY TABLE'))

    random.shuffle(blocks)
    path = os.path.join(OUT_DIR, 'oracle_audit.log')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(blocks) + '\n')
    print(f"생성: {path} ({len(blocks)}블록)")


# ── 3. MSSQL Audit 로그 ───────────────────────────────────

def make_mssql_audit_log():
    lines = []

    def mssql_line(dt, user, sql, rows=None):
        ts = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        r = rows if rows is not None else random.randint(0, 10)
        return (
            f"{ts},MSSQLSERVER,Audit Login,,{user},DBSERVER02,,"
            f"LoginName={user};StatementText={sql};"
            f"RowsAffected={r};DatabaseName=CustomerDB;"
        )

    # 정상
    for _ in range(200):
        u = random.choice(USERS['normal'])
        dt = business_dt()
        sql = random.choice(NORMAL_QUERIES)
        lines.append(mssql_line(dt, u, sql))

    # emp003: 과다조회
    burst_day = datetime(2024, 3, 7, 9, 30, 0)
    for i in range(160):
        dt = burst_day + timedelta(seconds=i * 22)
        cid = random.randint(1000, 9999)
        sql = f"SELECT name, phone, rrn FROM customers WHERE cust_id={cid}"
        lines.append(mssql_line(dt, 'emp003', sql, rows=random.randint(1, 4)))

    # emp007: 야간 PII
    for _ in range(30):
        dt = night_dt()
        cid = random.randint(1000, 9999)
        sql = f"SELECT cust_name, rrn, email, address FROM members WHERE id={cid}"
        lines.append(mssql_line(dt, 'emp007', sql, rows=random.randint(1, 8)))

    # admin01: 대량 조회
    for _ in range(12):
        dt = business_dt()
        sql = random.choice(BULK_QUERIES)
        lines.append(mssql_line(dt, 'admin01', sql, rows=random.randint(800, 6000)))

    lines.sort()
    path = os.path.join(OUT_DIR, 'mssql_audit.log')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"생성: {path} ({len(lines)}줄)")


# ── 4. 비정형 텍스트 로그 ─────────────────────────────────

def make_unstructured_log():
    lines = []
    phones  = ['010-3456-7890', '010-9876-5432', '010-1111-2222',
               '011-234-5678',  '010-5555-6666']
    emails  = ['kim.gil@company.com', 'lee.jung@example.co.kr',
               'park.s@test.org']
    names   = ['김길동', '이정희', '박수민', '최영식', '정다은']
    addrs   = ['서울시 강남구 테헤란로 152',
               '부산시 해운대구 센텀중앙로 55',
               '경기도 성남시 분당구 판교로 235']

    # 정상 비정형 로그
    normal_msgs = [
        "시스템 점검이 완료되었습니다. 서비스를 재개합니다.",
        "배치 작업 실행 완료 - 처리건수: {}건".format,
        "사용자 로그인: {} 접속 성공".format,
        "파일 업로드 완료: report_{}.pdf".format,
        "캐시 갱신 완료 - TTL: {}초".format,
        "API 호출 성공: /api/v1/products - 응답시간 {}ms".format,
    ]

    for _ in range(150):
        dt = business_dt()
        ts = dt.strftime('[%Y-%m-%d %H:%M:%S]')
        msg_fn = random.choice(normal_msgs)
        if callable(msg_fn):
            msg = msg_fn(random.randint(1, 9999))
        else:
            msg = msg_fn
        lines.append(f"{ts} INFO {msg}")

    # 고객 정보 노출 - 직접 전화번호/이름 포함
    pii_templates = [
        "[{}] INFO 고객 상담 완료: {} ({}) - 처리결과: 접수",
        "[{}] INFO 배송 알림 발송: {} / {} / {}",
        "[{}] WARN 고객 인증 실패: {} ({})",
        "[{}] INFO 회원 정보 조회: 이름={} 전화={} 이메일={}",
        "[{}] INFO 주문 처리: 고객명={} 연락처={} 주소={}",
    ]

    # emp007: 야간 고객정보 접근 로그
    for _ in range(25):
        dt = night_dt()
        ts = dt.strftime('%Y-%m-%d %H:%M:%S')
        name  = random.choice(names)
        phone = random.choice(phones)
        email = random.choice(emails)
        addr  = random.choice(addrs)
        tmpl  = random.choice(pii_templates)
        if '{}' in tmpl:
            parts = tmpl.count('{}')
            vals  = [ts, name, phone, email, addr][:parts]
            line  = tmpl.format(*vals)
        else:
            line = f"[{ts}] INFO 접근: {name} {phone}"
        lines.append(line)

    # 주민번호 직접 포함 (비정형)
    for rrn in VALID_RRNS[:3]:
        dt = rand_dt()
        ts = dt.strftime('[%Y-%m-%d %H:%M:%S]')
        lines.append(f"{ts} INFO 신원 확인 완료: 주민번호 {rrn} 처리됨")

    # 카드번호 직접 포함
    for card in VALID_CARDS[:2]:
        dt = rand_dt()
        ts = dt.strftime('[%Y-%m-%d %H:%M:%S]')
        lines.append(f"{ts} INFO 결제 처리: 카드번호 {card} 승인완료")

    # 전화번호 다양한 형식
    phone_variants = [
        '010 1234 5678',    # 공백 구분
        '01012345678',      # 붙여쓰기
        '02-555-1234',      # 서울 지역번호
        '031-987-6543',     # 경기 지역번호
    ]
    for ph in phone_variants:
        dt = rand_dt()
        ts = dt.strftime('[%Y-%m-%d %H:%M:%S]')
        lines.append(f"{ts} DEBUG 연락처 확인: {ph} 문자 발송 요청")

    lines.sort()
    path = os.path.join(OUT_DIR, 'unstructured.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"생성: {path} ({len(lines)}줄)")


# ── 5. 한글 숫자 PII 로그 ─────────────────────────────────

def make_korean_digits_log():
    """Log4j 형식으로 PII가 한글 숫자로 기록된 로그."""
    lines = []
    levels = ['INFO', 'DEBUG', 'WARN']

    # 한글 숫자 전화번호 변형
    korean_phones = [
        '공일공-일이삼사-오육칠팔',          # 010-1234-5678
        '공일공 일이삼사 오육칠팔',           # 010 1234 5678 (공백)
        '공일일-구팔칠-육오사삼',             # 011-987-6543
        '영일영-일일일일-이이이이',            # 010-1111-2222
        '공일육-삼사오-육칠팔구',             # 016-345-6789
        '공 일 공 일 이 삼 사 오 육 칠 팔',   # 공백 분리
    ]

    # 한글 숫자 주민번호 (유효 주민번호를 한글로)
    # 800101-1000008 → 팔공공일공일-일공공공공공팔
    korean_rrns = [
        '팔공공일공일-일공공공공공팔',   # 800101-1000008
        '구공공삼일오-이일공공공공일',   # 900315-2100001
        '팔오공육공일-일구팔칠육오공',   # 850601-1987650
    ]

    # 한글 숫자 카드번호 (4111-1111-1111-1111)
    korean_cards = [
        '사일일일-일일일일-일일일일-일일일일',    # 4111-1111-1111-1111
        '사오삼이-공일오일-일이팔삼-공삼육육',    # 4532-0151-1283-0366 (Luhn valid)
    ]

    users = ['sysadmin', 'batch01', 'monitor', 'emp007', 'admin01']

    # Log4j 형식: 날짜 시간 레벨 [스레드] 클래스 - 메시지
    def log4j(dt, level, thread, clazz, msg):
        ts = dt.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        return f"{ts} {level:<5} [{thread}] {clazz} - {msg}"

    # 정상 로그
    for _ in range(100):
        dt = business_dt()
        level = random.choice(levels)
        thread = f"pool-{random.randint(1,4)}-thread-{random.randint(1,8)}"
        clazz = random.choice(['com.example.UserService', 'com.example.OrderService',
                                'com.example.BatchJob', 'com.example.ApiGateway'])
        msg = random.choice([
            f"사용자 로그인 처리 완료 - user_id={random.randint(1000,9999)}",
            f"주문 처리 완료 - order_id={random.randint(10000,99999)} 상태=완료",
            f"배치 작업 시작 - 처리 예정 건수={random.randint(10,500)}",
            f"API 응답 시간: {random.randint(50,2000)}ms",
            f"캐시 히트율: {random.randint(60,99)}%",
        ])
        lines.append(log4j(dt, level, thread, clazz, msg))

    # 한글 숫자 전화번호 로그
    for _ in range(30):
        dt = rand_dt()
        level = 'INFO'
        thread = f"http-{random.randint(1, 16)}"
        clazz = 'com.example.CustomerService'
        phone_kr = random.choice(korean_phones)
        user = random.choice(users)
        msg = random.choice([
            f"고객 연락처 조회 - 담당자: {user} 전화번호: {phone_kr}",
            f"SMS 발송 요청 - 수신번호: {phone_kr} 발신자: {user}",
            f"고객 정보 로그 - 연락처={phone_kr} 처리자={user}",
        ])
        lines.append(log4j(dt, level, thread, clazz, msg))

    # 한글 숫자 주민번호 로그
    for _ in range(15):
        dt = night_dt()  # 야간에 주민번호 접근
        level = 'WARN'
        thread = f"scheduler-{random.randint(1, 3)}"
        clazz = 'com.example.IdentityVerifier'
        rrn_kr = random.choice(korean_rrns)
        user = random.choice(['emp007', 'batch01'])
        msg = f"신원 검증 처리 - 대상: {rrn_kr} 처리자: {user}"
        lines.append(log4j(dt, level, thread, clazz, msg))

    # 한글 숫자 카드번호 로그
    for _ in range(10):
        dt = rand_dt()
        level = 'INFO'
        thread = f"payment-{random.randint(1, 4)}"
        clazz = 'com.example.PaymentProcessor'
        card_kr = random.choice(korean_cards)
        msg = f"결제 수단 확인 - 카드번호: {card_kr} 결제 처리 시작"
        lines.append(log4j(dt, level, thread, clazz, msg))

    # 혼합 (아라비아 + 한글 숫자)
    for _ in range(10):
        dt = rand_dt()
        level = 'INFO'
        thread = f"api-{random.randint(1, 8)}"
        clazz = 'com.example.MixedLogger'
        phone_mixed = '010-일이삼사-오육칠팔'
        msg = f"혼합 형식 연락처 처리: {phone_mixed}"
        lines.append(log4j(dt, level, thread, clazz, msg))

    lines.sort()
    path = os.path.join(OUT_DIR, 'korean_digits.log')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"생성: {path} ({len(lines)}줄)")


# ── 메인 ──────────────────────────────────────────────────

if __name__ == '__main__':
    random.seed(42)
    print("샘플 로그 생성 중...")
    make_postgresql_log()
    make_oracle_audit_log()
    make_mssql_audit_log()
    make_unstructured_log()
    make_korean_digits_log()
    print("\n완료! sample_logs/ 폴더를 확인하세요.")
    print("  postgresql.log   - PostgreSQL 서버 로그 (statement/pgaudit)")
    print("  oracle_audit.log - Oracle 감사 로그 (멀티라인 블록)")
    print("  mssql_audit.log  - MSSQL 감사 로그 (CSV 형식)")
    print("  unstructured.txt - 비정형 텍스트 (직접 PII 포함)")
    print("  korean_digits.log - Log4j + 한글숫자 PII")
