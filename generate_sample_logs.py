#!/usr/bin/env python3
"""
테스트용 샘플 로그 파일 생성기.
실제 개인정보가 아닌 가상의 테스트 데이터를 생성합니다.
"""
from __future__ import annotations
import random
import os
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

# 테스트 사용자 목록
USERS = [
    'emp001', 'emp002', 'emp003', 'emp004', 'emp005',
    'emp006', 'emp007', 'emp008', 'emp009', 'emp010',
    'admin01', 'dba_user', 'analyst1',
]

# 가상 고객 테이블/정보
TABLES = ['customers', 'members', 'personal_info', 'accounts', 'orders', 'employees']
SENSITIVE_TABLES = ['customers', 'members', 'personal_info']

# 가상 주민등록번호 (테스트용 - 체크섬 맞춤)
FAKE_RRNS = [
    '800101-1234567',  # 유효한 형식의 테스트 데이터
    '901215-2345678',
    '850601-1987654',
]

# 가상 전화번호 (테스트용)
FAKE_PHONES = [
    '010-1234-5678', '010-9876-5432', '02-345-6789',
    '031-234-5678', '010-5555-1234',
]

# 가상 이름 (테스트용)
FAKE_NAMES = ['홍길동', '김철수', '이영희', '박민준', '최수진']

# 가상 계좌번호 (테스트용)
FAKE_ACCOUNTS = ['123-456-789012', '987-654-321098']

# 가상 이메일 (테스트용)
FAKE_EMAILS = ['test.user@example.com', 'hong.gildong@company.co.kr', 'kim.chulsoo@test.org']


def random_datetime(start_date: datetime, end_date: datetime, hour_bias=None) -> datetime:
    """기간 내 랜덤 datetime 생성. hour_bias가 있으면 해당 시간대 편향."""
    delta = end_date - start_date
    random_seconds = random.randint(0, int(delta.total_seconds()))
    dt = start_date + timedelta(seconds=random_seconds)
    if hour_bias:
        # 야간 편향
        dt = dt.replace(hour=random.choice(hour_bias))
    return dt


def generate_mysql_log(output_path: str, start_date: datetime, end_date: datetime, num_lines: int = 5000):
    """MySQL General Query Log 형식 샘플 생성"""
    lines = []

    # 정상 사용자 (대부분 정상 범위)
    normal_users = USERS[:10]
    # 이상 사용자: emp003 (과다조회), emp007 (야간 PII 조회), admin01 (대량 조회)
    suspicious_users = ['emp003', 'emp007', 'admin01']

    thread_id = 1000
    current_time = start_date

    for i in range(num_lines):
        current_time += timedelta(seconds=random.randint(1, 300))
        if current_time > end_date:
            current_time = start_date + timedelta(hours=random.randint(1, 100))

        ts = current_time.strftime('%Y-%m-%dT%H:%M:%S.000000Z')
        tid = str(thread_id + random.randint(0, 50))

        # 사용자 선택
        if i % 20 == 0:  # 5%: 이상 사용자
            user = random.choice(suspicious_users)
        else:
            user = random.choice(normal_users)

        # Connect 이벤트 (가끔)
        if random.random() < 0.05:
            lines.append(f"{ts}    {tid} Connect\t{user}@localhost on company_db")

        # Query 이벤트 + 결과 건수 (Rows_sent 패턴)
        table = random.choice(TABLES)
        result_rows = None

        if user == 'emp003':
            # emp003: 반복 조회 + SELECT * (노출형)
            sql = f"SELECT * FROM customers WHERE status='active' LIMIT 100"
            result_rows = random.randint(80, 100)
        elif user == 'emp007' and random.random() < 0.3:
            # emp007: 야간에 SELECT절 개인정보 직접 노출
            name = random.choice(FAKE_NAMES)
            sql = f"SELECT name, phone, address, email FROM personal_info WHERE customer_name='{name}'"
            result_rows = random.randint(1, 50)
            ts_night = current_time.replace(hour=random.choice([0, 1, 2, 22, 23]))
            ts = ts_night.strftime('%Y-%m-%dT%H:%M:%S.000000Z')
        elif user == 'admin01' and random.random() < 0.2:
            # admin01: 대량 조회 + PII SELECT (고위험)
            row_limit = random.randint(5000, 30000)
            sql = f"SELECT name, phone, rrn, address FROM members LIMIT {row_limit}"
            result_rows = row_limit
        else:
            # 일반 쿼리 - WHERE 조건으로 검색 (PII 노출 아님)
            col = random.choice(['id', 'status', 'created_at', 'category'])
            val = random.randint(1, 10000)
            sql = f"SELECT id, name FROM {table} WHERE {col}={val}"
            result_rows = random.randint(0, 20)

        # Rows_sent 패턴으로 결과 건수 기록 (MySQL slow query log 형식)
        if result_rows is not None:
            lines.append(f"# Rows_sent: {result_rows}  Rows_examined: {result_rows * random.randint(1,5)}")
        lines.append(f"{ts}    {tid} Query\t{sql}")

    # emp003 과다조회 시뮬레이션: 하루에 600건 이상 추가 (SELECT절 PII 포함)
    burst_date = start_date + timedelta(days=random.randint(1, 10))
    burst_ts_base = burst_date.replace(hour=10, minute=0, second=0)
    for j in range(650):
        bt = burst_ts_base + timedelta(seconds=j * 5)
        bts = bt.strftime('%Y-%m-%dT%H:%M:%S.000000Z')
        btid = str(thread_id + 99)
        rows_sent = random.randint(5, 50)
        lines.append(f"{bts}    {btid} Connect\temp003@localhost on company_db")
        lines.append(f"# Rows_sent: {rows_sent}  Rows_examined: {rows_sent * 3}")
        lines.append(f"{bts}    {btid} Query\tSELECT cust_name, phone, address FROM customers WHERE dept_id={j}")

    # 정렬 (실제 로그는 시간순)
    # 간단하게 그냥 씀 (실제 로그는 무순서일 수도 있음)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"  MySQL 로그 생성: {output_path} ({len(lines):,}줄)")


def generate_app_log(output_path: str, start_date: datetime, end_date: datetime, num_lines: int = 3000):
    """애플리케이션 로그 형식 (Log4j) 샘플 생성"""
    lines = []
    levels = ['INFO', 'INFO', 'INFO', 'WARN', 'ERROR', 'DEBUG']

    for i in range(num_lines):
        dt = random_datetime(start_date, end_date)
        ts = dt.strftime('%Y-%m-%d %H:%M:%S,') + f'{random.randint(0, 999):03d}'
        level = random.choice(levels)
        user = random.choice(USERS)
        thread = f"http-thread-{random.randint(1, 20)}"
        logger = random.choice(['com.company.CustomerService', 'com.company.AuthFilter',
                                'com.company.DataAccessLayer', 'com.company.ReportService'])

        if random.random() < 0.15:
            # PII 포함 로그 + 결과 건수 포함
            r = random.random()
            if r < 0.3:
                # 고객 목록 조회 - 결과 건수 포함 (SELECT절 노출형)
                result_cnt = random.randint(100, 8000)
                msg = (f"고객 목록 조회 완료: userid={user} "
                       f"query=SELECT name,phone,email FROM customers "
                       f"결과 {result_cnt}건 반환 elapsed={random.randint(10,500)}ms")
            elif r < 0.5:
                email = random.choice(FAKE_EMAILS)
                msg = f"Customer lookup for user={user} email={email} from IP=192.168.1.{random.randint(1,50)}"
            elif r < 0.7:
                phone = random.choice(FAKE_PHONES)
                result_cnt = random.randint(1, 30)
                msg = (f"Processing request: userid={user} customer_phone={phone} "
                       f"action=view_profile returned {result_cnt} rows")
            else:
                name = random.choice(FAKE_NAMES)
                msg = f"Data access: employee_id={user} customer_name={name} accessed personal records"
        else:
            msgs = [
                f"Request processed successfully in {random.randint(10, 500)}ms userid={user}",
                f"Cache miss for key=user:{user}:profile",
                f"Login successful userid={user} from 192.168.1.{random.randint(1,50)}",
                f"Session created for user={user} sessionId=sess_{random.randint(10000,99999)}",
                f"Query executed in {random.randint(5, 200)}ms for userid={user} resultCount={random.randint(0,5)}",
            ]
            msg = random.choice(msgs)

        lines.append(f"{ts} {level:<5} [{thread}] {logger} - {msg}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"  앱 로그 생성: {output_path} ({len(lines):,}줄)")


def generate_web_access_log(output_path: str, start_date: datetime, end_date: datetime, num_lines: int = 2000):
    """Apache Combined Log Format 샘플 생성"""
    lines = []
    ips = [f"192.168.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(20)]
    paths = [
        '/api/v1/customers/search',
        '/api/v1/members/profile',
        '/api/v1/personal/info',
        '/static/js/app.js',
        '/static/css/style.css',
        '/admin/users/list',
        '/api/v1/reports/export',
    ]
    methods = ['GET', 'POST', 'GET', 'GET', 'GET']
    statuses = ['200', '200', '200', '304', '404', '500']

    for i in range(num_lines):
        dt = random_datetime(start_date, end_date)
        ts = dt.strftime('%d/%b/%Y:%H:%M:%S +0900')
        ip = random.choice(ips)
        user = random.choice(USERS) if random.random() < 0.7 else '-'
        method = random.choice(methods)
        path = random.choice(paths)
        status = random.choice(statuses)
        size = random.randint(200, 50000)

        # PII가 URL에 포함되는 경우
        if random.random() < 0.1 and 'search' in path:
            phone = random.choice(FAKE_PHONES)
            path = f"{path}?phone={phone}&user={user}"

        lines.append(f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"')

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"  웹 접근 로그 생성: {output_path} ({len(lines):,}줄)")


def main():
    print("테스트용 샘플 로그 생성 중...")
    output_dir = Path('./sample_logs')
    output_dir.mkdir(exist_ok=True)

    # 분석 기간 설정 (최근 2개월)
    end_date = datetime(2024, 3, 21, 23, 59, 59)
    start_date = datetime(2024, 2, 1, 0, 0, 0)

    generate_mysql_log(
        str(output_dir / 'mysql_audit.log'),
        start_date, end_date,
        num_lines=8000
    )

    generate_app_log(
        str(output_dir / 'application.log'),
        start_date, end_date,
        num_lines=5000
    )

    generate_web_access_log(
        str(output_dir / 'access.log'),
        start_date, end_date,
        num_lines=3000
    )

    print("\n샘플 로그 생성 완료!")
    print("\n분석 실행 예시:")
    print("  python main.py \\")
    print("    --log-files sample_logs/mysql_audit.log sample_logs/application.log sample_logs/access.log \\")
    print("    --start-date 2024-02-01 --end-date 2024-03-21 \\")
    print("    --output-dir ./reports")


if __name__ == '__main__':
    main()
