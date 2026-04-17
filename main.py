#!/usr/bin/env python3
"""
개인정보 오남용·과다조회 점검 시스템
Usage: python main.py --log-files <파일1> [<파일2> ...] --start-date YYYY-MM-DD --end-date YYYY-MM-DD [options]
"""
from __future__ import annotations
import sys
import os
import glob
import time
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 프로젝트 루트를 sys.path에 추가
sys.path.insert(0, str(Path(__file__).parent))

from config import load_threshold_overrides, THRESHOLDS
from utils.date_utils import parse_date_arg, in_date_range
from pipeline.stream_reader import stream_lines
from parsers.auto_detector import detect_format, ALL_PARSERS
from parsers.generic_parser import GenericParser
from detectors.pii_detector import scan_event
from detectors.access_counter import AccessCounter
from detectors.anomaly_scorer import score_all
from pipeline.aggregator import build_user_summaries, create_pii_finding_from_event
from models.log_event import LogEvent
from models.finding import Finding
from reports.excel_reporter import generate_excel
from reports.html_reporter import generate_html
from history.manager import save_snapshot, find_snapshot, find_closest_snapshot, compute_deltas
from detectors.sql_clause_analyzer import analyze_sql


def parse_args():
    parser = argparse.ArgumentParser(
        description='개인정보 오남용·과다조회 점검 시스템',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python main.py --log-files /logs/*.log --start-date 2024-01-01 --end-date 2024-01-31
  python main.py --log-files app.log db.log --start-date 2024-03-01 --end-date 2024-03-21 --output-dir ./reports/
  python main.py --log-files audit.log --start-date 2024-01-01 --end-date 2024-12-31 --format db --report-format html
        """
    )
    parser.add_argument('--log-files', nargs='+', required=True,
                        help='분석할 로그 파일 경로 (glob 패턴 지원: /logs/*.log)')
    parser.add_argument('--start-date', required=True,
                        help='분석 시작 날짜 (YYYY-MM-DD)')
    parser.add_argument('--end-date', required=True,
                        help='분석 종료 날짜 (YYYY-MM-DD)')
    parser.add_argument('--output-dir', default='./reports',
                        help='보고서 출력 디렉토리 (기본: ./reports)')
    parser.add_argument('--format', choices=['auto', 'db', 'web', 'app', 'generic'],
                        default='auto', help='로그 형식 (기본: auto 자동감지)')
    parser.add_argument('--report-format', choices=['html', 'excel', 'both'],
                        default='both', help='보고서 형식 (기본: both)')
    parser.add_argument('--threshold-file', default=None,
                        help='임계값 오버라이드 JSON 파일 경로')
    parser.add_argument('--max-workers', type=int, default=4,
                        help='병렬 처리 스레드 수 (기본: 4)')
    parser.add_argument('--min-risk-level', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                        default='LOW', help='보고서에 포함할 최소 위험 등급 (기본: LOW)')
    return parser.parse_args()


def resolve_files(file_patterns: list[str]) -> list[str]:
    """glob 패턴을 포함한 파일 목록을 실제 파일 경로 목록으로 확장합니다."""
    resolved = []
    for pattern in file_patterns:
        matches = glob.glob(pattern)
        if matches:
            resolved.extend(matches)
        elif os.path.isfile(pattern):
            resolved.append(pattern)
        else:
            print(f"[경고] 파일을 찾을 수 없습니다: {pattern}")
    return sorted(set(resolved))


def process_file(
    file_path: str,
    parser,
    start_date,
    end_date,
    access_counter: AccessCounter,
) -> tuple[list[LogEvent], list[Finding], int, int]:
    """
    단일 파일을 처리합니다.
    Returns: (events, pii_findings, total_lines, skipped_lines)
    """
    events = []
    pii_findings = []
    total_lines = 0
    skipped_lines = 0
    context = {}  # 파서 상태 (멀티라인 레코드용)

    for line_no, line in stream_lines(file_path):
        total_lines += 1

        # 파서로 라인 파싱
        try:
            event = parser.parse_line(line, line_no, file_path, context)
        except Exception as e:
            skipped_lines += 1
            continue

        if event is None:
            skipped_lines += 1
            continue

        # 날짜 범위 필터
        if not in_date_range(event.timestamp, start_date, end_date):
            continue

        # PII 탐지
        pii_hits = scan_event(event)
        event.pii_hits = pii_hits

        # SQL 절 분석 - 결과 건수 기반 실효 노출량 계산
        if event.query_text:
            # 결과 건수: 파서가 extra에 저장한 값 우선, 없으면 raw_line에서 추출
            if event.extra.get('result_rows') is not None:
                sql_ctx = str(event.extra.get('result_rows', ''))
            else:
                sql_ctx = event.raw_line
            sa = analyze_sql(event.query_text, context_text=sql_ctx)
            event.result_row_count  = sa.result_row_count
            event.pii_select_fields = sa.select_pii_fields
            event.pii_where_fields  = sa.where_pii_fields
            event.is_select_star    = sa.is_select_star
            event.is_sensitive_table = sa.is_sensitive_table
            event.effective_pii_exposure = sa.effective_exposure
            event.exposure_type     = sa.exposure_type

        # PII Finding 생성
        if pii_hits:
            new_findings = create_pii_finding_from_event(event)
            pii_findings.extend(new_findings)

        # 접근 카운터 기록 (타임스탬프 있는 경우만)
        if event.timestamp and event.user_id:
            access_counter.record(event)

        events.append(event)

    return events, pii_findings, total_lines, skipped_lines


def print_banner():
    print("=" * 65)
    print("  개인정보 오남용·과다조회 점검 시스템")
    print("  Personal Information Misuse Detection System")
    print("=" * 65)


def print_summary(summaries, total_events, total_lines, elapsed, output_files):
    print()
    print("=" * 65)
    print("  점검 완료 요약")
    print("=" * 65)
    print(f"  총 로그 라인 수   : {total_lines:>12,} 줄")
    print(f"  총 분석 이벤트 수 : {total_events:>12,} 건")
    print(f"  총 사용자 수      : {len(summaries):>12,} 명")
    print(f"  소요 시간         : {elapsed:>11.1f} 초")

    if summaries:
        print()
        print("  위험 등급별 사용자 현황:")
        for level, label in [('CRITICAL', '위험'), ('HIGH', '고위험'), ('MEDIUM', '중위험'), ('LOW', '저위험')]:
            count = sum(1 for s in summaries if s.risk_level == level)
            bar = '#' * min(count, 30)
            print(f"    {label:6s} ({level:8s}): {count:4d}명  {bar}")

        print()
        print("  상위 위험 사용자 (Top 10):")
        print(f"  {'사원ID':<15} {'점수':>6} {'등급':>10} {'PII접촉':>8} {'이상건수':>8}")
        print("  " + "-" * 55)
        for s in summaries[:10]:
            print(f"  {s.user_id:<15} {s.risk_score:>6.1f} {s.risk_level:>10} {s.pii_event_count:>8,} {s.flagged_event_count:>8,}")

    print()
    print("  생성된 보고서:")
    for f in output_files:
        print(f"    - {f}")
    print("=" * 65)


def get_parser_for_format(format_name: str, file_path: str, force_format: str = 'auto'):
    """파서 인스턴스를 반환합니다."""
    from parsers.db_access_parser import DbAccessParser
    from parsers.web_access_parser import WebAccessParser
    from parsers.app_log_parser import AppLogParser

    if force_format == 'db':
        return DbAccessParser()
    elif force_format == 'web':
        return WebAccessParser()
    elif force_format == 'app':
        return AppLogParser()
    elif force_format == 'generic':
        return GenericParser()
    else:
        # auto 감지
        _, parser = detect_format(file_path)
        return parser


def main():
    print_banner()
    args = parse_args()

    # 임계값 오버라이드 적용
    if args.threshold_file:
        load_threshold_overrides(args.threshold_file)

    # 날짜 파싱
    try:
        start_date = parse_date_arg(args.start_date)
        end_date = parse_date_arg(args.end_date)
    except ValueError as e:
        print(f"[오류] {e}")
        sys.exit(1)

    if start_date > end_date:
        print("[오류] 시작 날짜가 종료 날짜보다 늦을 수 없습니다.")
        sys.exit(1)

    # 파일 목록 확인
    log_files = resolve_files(args.log_files)
    if not log_files:
        print("[오류] 분석할 로그 파일이 없습니다.")
        sys.exit(1)

    print(f"\n  분석 기간: {start_date} ~ {end_date}")
    print(f"  대상 파일: {len(log_files)}개")
    for f in log_files:
        size = os.path.getsize(f) / 1024 / 1024
        print(f"    - {f} ({size:.1f} MB)")
    print()

    # 출력 디렉토리 생성
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 전역 접근 카운터 (스레드 안전성을 위해 단일 인스턴스 사용)
    # 주의: 멀티스레드 환경에서 AccessCounter는 공유되므로 파일별 순차 처리
    access_counter = AccessCounter()
    all_events: list[LogEvent] = []
    all_pii_findings: list[Finding] = []
    total_lines = 0
    total_skipped = 0

    start_time = time.time()

    # 파일 처리 (I/O bound이므로 스레드 사용)
    print(f"[처리 시작] {len(log_files)}개 파일 분석 중...")

    # AccessCounter가 thread-safe하지 않으므로 파일별로 순차 처리
    # (병렬화가 필요하면 파일별 카운터를 병합하는 방식으로 확장 가능)
    for i, file_path in enumerate(log_files, 1):
        print(f"\n[{i}/{len(log_files)}] {Path(file_path).name}")
        parser = get_parser_for_format(args.format, file_path, args.format)

        events, pii_findings, lines, skipped = process_file(
            file_path, parser, start_date, end_date, access_counter
        )

        all_events.extend(events)
        all_pii_findings.extend(pii_findings)
        total_lines += lines
        total_skipped += skipped

        print(f"    완료: {lines:,}줄 처리, {len(events):,}건 이벤트, {len(pii_findings):,}건 PII 검출")

    elapsed_parse = time.time() - start_time
    print(f"\n[파싱 완료] {total_lines:,}줄 처리 완료 ({elapsed_parse:.1f}초, {total_lines/max(elapsed_parse,0.01)/1000:.0f}k줄/초)")

    # 사용자별 집계
    print("\n[집계] 사용자별 통계 집계 중...")
    summaries = build_user_summaries(all_events, all_pii_findings, access_counter)

    # 위험 점수 산정
    print("[채점] 위험 점수 산정 중...")
    summaries = score_all(summaries)

    # 최소 위험 등급 필터 적용
    level_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    min_idx = level_order.index(args.min_risk_level)
    filtered_summaries = [
        s for s in summaries
        if level_order.index(s.risk_level) >= min_idx
    ]
    print(f"[필터] {len(summaries)}명 중 {len(filtered_summaries)}명 보고서 포함 (기준: {args.min_risk_level} 이상)")

    # ── 이력 비교 분석 ───────────────────────────────────────
    history_dir = output_dir.parent / 'history'
    period_days = (end_date - start_date).days + 1

    # 비교 대상 기간: 동일 길이의 기간을 7일/30일 앞으로 이동
    week_start  = start_date - timedelta(days=7)
    week_end    = end_date   - timedelta(days=7)
    month_start = start_date - timedelta(days=30)
    month_end   = end_date   - timedelta(days=30)

    print(f"\n[이력 비교] 1주 전 기간: {week_start} ~ {week_end}")
    prior_week = find_snapshot(history_dir, week_start, week_end)
    if not prior_week:
        prior_week, matched = find_closest_snapshot(history_dir, week_start, week_end)
        if prior_week:
            print(f"  → 근접 기간 매칭: {matched}")
        else:
            print(f"  → 이력 없음 (처음 실행하거나 해당 기간 데이터 없음)")

    print(f"[이력 비교] 1개월 전 기간: {month_start} ~ {month_end}")
    prior_month = find_snapshot(history_dir, month_start, month_end)
    if not prior_month:
        prior_month, matched = find_closest_snapshot(history_dir, month_start, month_end)
        if prior_month:
            print(f"  → 근접 기간 매칭: {matched}")
        else:
            print(f"  → 이력 없음")

    deltas_week  = compute_deltas(filtered_summaries, prior_week)  if prior_week  else {}
    deltas_month = compute_deltas(filtered_summaries, prior_month) if prior_month else {}

    if deltas_week:
        print(f"  1주 전 비교 가능 사용자: {len(deltas_week)}명")
    if deltas_month:
        print(f"  1개월 전 비교 가능 사용자: {len(deltas_month)}명")

    # 현재 결과 저장 (비교 계산 이후에 저장해야 자기 자신과 비교 방지)
    print("[이력 저장] 현재 분석 결과 저장 중...")
    save_snapshot(history_dir, start_date, end_date, summaries,
                  total_events=len(all_events), total_lines=total_lines)
    # ── 이력 비교 분석 끝 ────────────────────────────────────

    # 보고서 생성
    ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_files = []

    if args.report_format in ('excel', 'both'):
        excel_path = str(output_dir / f"개인정보점검보고서_{args.start_date}_{args.end_date}_{ts_str}.xlsx")
        print(f"\n[보고서] Excel 생성 중...")
        result = generate_excel(
            filtered_summaries, start_date, end_date, excel_path,
            total_events=len(all_events), total_lines=total_lines,
            deltas_week=deltas_week, deltas_month=deltas_month,
            week_period=f"{week_start} ~ {week_end}",
            month_period=f"{month_start} ~ {month_end}",
        )
        if result:
            output_files.append(result)
            print(f"    저장: {result}")

    if args.report_format in ('html', 'both'):
        html_path = str(output_dir / f"개인정보점검보고서_{args.start_date}_{args.end_date}_{ts_str}.html")
        print(f"[보고서] HTML 생성 중...")
        result = generate_html(
            filtered_summaries, start_date, end_date, html_path,
            total_events=len(all_events), total_lines=total_lines,
            deltas_week=deltas_week, deltas_month=deltas_month,
            week_period=f"{week_start} ~ {week_end}",
            month_period=f"{month_start} ~ {month_end}",
        )
        if result:
            output_files.append(result)
            print(f"    저장: {result}")

    elapsed_total = time.time() - start_time
    print_summary(filtered_summaries, len(all_events), total_lines, elapsed_total, output_files)

    # 위험 등급 CRITICAL/HIGH 사용자가 있으면 경고
    critical_count = sum(1 for s in filtered_summaries if s.risk_level == 'CRITICAL')
    if critical_count > 0:
        print(f"\n  [!] 경고: {critical_count}명의 위험(CRITICAL) 등급 사용자가 발견되었습니다.")
        print("       Excel 보고서의 '5. 소명 요청 양식' 시트를 확인하세요.")

    return 0


if __name__ == '__main__':
    sys.exit(main())
