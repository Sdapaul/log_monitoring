"""
파이프라인 실행기 - main.py와 web_app.py에서 공유하는 핵심 분석 로직
"""
from __future__ import annotations
import os
import glob
import time
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Callable, Optional

from utils.date_utils import in_date_range
from pipeline.stream_reader import stream_lines
from parsers.auto_detector import detect_format
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
from history.daily_counts import load_daily_counts, save_daily_counts
from detectors.sql_clause_analyzer import analyze_sql

# 점검 항목별 Finding 카테고리 매핑
MISUSE_CATEGORIES  = {'PII_EXPOSURE', 'AFTER_HOURS', 'PII_RECORD_EXPOSURE'}
EXCESS_CATEGORIES  = {'EXCESSIVE_ACCESS', 'BULK_EXPORT'}


def get_parser(file_path: str, force_format: str = 'auto'):
    """파서 인스턴스를 반환합니다."""
    from parsers.db_access_parser import DbAccessParser
    from parsers.web_access_parser import WebAccessParser
    from parsers.app_log_parser import AppLogParser

    if force_format in ('db', 'postgresql'):
        return DbAccessParser()
    elif force_format == 'web':
        return WebAccessParser()
    elif force_format == 'app':
        return AppLogParser()
    elif force_format == 'generic':
        return GenericParser()
    else:
        _, parser = detect_format(file_path)
        return parser


def process_file(
    file_path: str,
    parser,
    start_date,
    end_date,
    access_counter: AccessCounter,
) -> tuple[list[LogEvent], list[Finding], int, int]:
    """단일 파일 처리. Returns (events, pii_findings, total_lines, skipped_lines)"""
    events = []
    pii_findings = []
    total_lines = 0
    skipped_lines = 0
    context = {}

    for line_no, line in stream_lines(file_path):
        total_lines += 1
        try:
            event = parser.parse_line(line, line_no, file_path, context)
        except Exception:
            skipped_lines += 1
            continue

        if event is None:
            skipped_lines += 1
            continue

        if not in_date_range(event.timestamp, start_date, end_date):
            continue

        pii_hits = scan_event(event)
        event.pii_hits = pii_hits

        if event.query_text:
            if event.extra.get('result_rows') is not None:
                sql_ctx = str(event.extra.get('result_rows', ''))
            else:
                sql_ctx = event.raw_line
            sa = analyze_sql(event.query_text, context_text=sql_ctx)
            event.result_row_count       = sa.result_row_count
            event.pii_select_fields      = sa.select_pii_fields
            event.pii_where_fields       = sa.where_pii_fields
            event.is_select_star         = sa.is_select_star
            event.is_sensitive_table     = sa.is_sensitive_table
            event.effective_pii_exposure = sa.effective_exposure
            event.exposure_type          = sa.exposure_type

        if pii_hits:
            new_findings = create_pii_finding_from_event(event)
            pii_findings.extend(new_findings)

        if event.timestamp and event.user_id:
            access_counter.record(event)

        events.append(event)

    return events, pii_findings, total_lines, skipped_lines


def _apply_selection_filter(summaries, check_misuse: bool, check_excess: bool):
    """
    점검 항목 선택에 따라 UserSummary의 findings와 관련 필드를 조정합니다.
    score_all() 호출 전에 실행되어야 합니다.
    """
    if check_misuse and check_excess:
        return  # 둘 다 선택 → 필터 없음

    allowed_cats = set()
    if check_misuse:
        allowed_cats |= MISUSE_CATEGORIES
    if check_excess:
        allowed_cats |= EXCESS_CATEGORIES

    for s in summaries:
        # Findings 필터
        s.findings = [f for f in s.findings if f.category in allowed_cats]

        # 오남용 관련 필드 초기화 (과다조회만 선택한 경우)
        if not check_misuse:
            s.total_pii_records_exposed = 0
            s.max_single_query_exposure = 0
            s.pii_event_count           = 0
            s.after_hours_count         = 0  # 야간 PII 조회는 오남용 구성 요소
            s.pii_types_seen            = set()

        # 과다조회 관련 필드 초기화 (오남용만 선택한 경우)
        if not check_excess:
            s.max_queries_per_day    = 0
            s.max_queries_per_hour   = 0
            s.bulk_export_count      = 0
            s.unique_targets_per_day = 0


def run_analysis(
    log_files: list[str],
    start_date,
    end_date,
    output_dir: Path,
    check_misuse: bool = True,
    check_excess: bool = True,
    min_risk_level: str = 'LOW',
    log_format: str = 'auto',
    report_formats: list[str] = None,
    progress: Callable[[int, str], None] = None,
    history_dir: Optional[Path] = None,
    save_history: bool = True,
) -> dict:
    """
    핵심 분석 파이프라인 실행.

    Args:
        log_files:     분석할 로그 파일 경로 목록
        start_date:    분석 시작 날짜 (date 또는 str)
        end_date:      분석 종료 날짜 (date 또는 str)
        output_dir:    보고서 출력 디렉토리
        check_misuse:  개인정보 오남용 점검 여부
        check_excess:  과다조회 점검 여부
        min_risk_level: 보고서에 포함할 최소 위험 등급
        log_format:    로그 형식 강제 지정 ('auto'|'db'|'web'|'app'|'generic')
        report_formats: 생성할 보고서 형식 목록 ['html', 'excel']
        progress:      진행률 콜백 (percent: int, message: str) -> None
        history_dir:   이력 저장 디렉토리 (None이면 output_dir.parent/history)
        save_history:  현재 결과를 이력으로 저장할지 여부

    Returns:
        dict with keys:
          summaries, report_files, total_events, total_lines, elapsed,
          deltas_week, deltas_month, week_period, month_period,
          check_misuse, check_excess
    """
    if report_formats is None:
        report_formats = ['html', 'excel']
    if history_dir is None:
        history_dir = output_dir.parent / 'history'

    from utils.date_utils import parse_date_arg
    if isinstance(start_date, str):
        start_date = parse_date_arg(start_date)
    if isinstance(end_date, str):
        end_date = parse_date_arg(end_date)

    def prog(pct: int, msg: str):
        if progress:
            progress(pct, msg)

    output_dir.mkdir(parents=True, exist_ok=True)
    access_counter = AccessCounter()
    all_events: list[LogEvent] = []
    all_pii_findings: list[Finding] = []
    total_lines = 0

    start_time = time.time()
    n = len(log_files)

    prog(3, f"{n}개 파일 분석 준비 중...")

    for i, file_path in enumerate(log_files):
        fname = Path(file_path).name
        pct = 5 + int((i / n) * 55)
        prog(pct, f"[{i+1}/{n}] {fname} 처리 중...")

        parser = get_parser(file_path, log_format)
        events, pii_findings, lines, _ = process_file(
            file_path, parser, start_date, end_date, access_counter
        )
        all_events.extend(events)
        all_pii_findings.extend(pii_findings)
        total_lines += lines

    prog(60, "일별 추세 이상 탐지 중...")
    hist_daily = load_daily_counts(history_dir)
    access_counter.finalize(target_date=str(end_date), historical_daily=hist_daily)
    save_daily_counts(history_dir, access_counter._daily_counts)

    prog(62, "사용자별 통계 집계 중...")
    summaries = build_user_summaries(all_events, all_pii_findings, access_counter)

    prog(67, "점검 항목 필터 적용 중...")
    _apply_selection_filter(summaries, check_misuse, check_excess)

    prog(70, "위험 점수 산정 중...")
    summaries = score_all(summaries)

    # 최소 위험 등급 필터
    level_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    min_idx = level_order.index(min_risk_level)
    filtered = [s for s in summaries if level_order.index(s.risk_level) >= min_idx]

    # ── 이력 비교 분석 ─────────────────────────────────────
    prog(73, "이력 비교 분석 중...")
    week_start  = start_date - timedelta(days=7)
    week_end    = end_date   - timedelta(days=7)
    month_start = start_date - timedelta(days=30)
    month_end   = end_date   - timedelta(days=30)

    prior_week = find_snapshot(history_dir, week_start, week_end)
    if not prior_week:
        prior_week, _ = find_closest_snapshot(history_dir, week_start, week_end)

    prior_month = find_snapshot(history_dir, month_start, month_end)
    if not prior_month:
        prior_month, _ = find_closest_snapshot(history_dir, month_start, month_end)

    deltas_week  = compute_deltas(filtered, prior_week)  if prior_week  else {}
    deltas_month = compute_deltas(filtered, prior_month) if prior_month else {}
    week_period  = f"{week_start} ~ {week_end}"
    month_period = f"{month_start} ~ {month_end}"

    if save_history:
        prog(77, "이력 저장 중...")
        save_snapshot(history_dir, start_date, end_date, summaries,
                      total_events=len(all_events), total_lines=total_lines)

    # ── 보고서 생성 ────────────────────────────────────────
    ts_str    = datetime.now().strftime('%Y%m%d_%H%M%S')
    start_str = str(start_date)
    end_str   = str(end_date)
    report_files = []

    if 'excel' in report_formats:
        prog(82, "Excel 보고서 생성 중...")
        path = str(output_dir / f"개인정보점검보고서_{start_str}_{end_str}_{ts_str}.xlsx")
        result = generate_excel(
            filtered, start_date, end_date, path,
            total_events=len(all_events), total_lines=total_lines,
            deltas_week=deltas_week, deltas_month=deltas_month,
            week_period=week_period, month_period=month_period,
        )
        if result:
            report_files.append(result)

    if 'html' in report_formats:
        prog(92, "HTML 보고서 생성 중...")
        path = str(output_dir / f"개인정보점검보고서_{start_str}_{end_str}_{ts_str}.html")
        result = generate_html(
            filtered, start_date, end_date, path,
            total_events=len(all_events), total_lines=total_lines,
            deltas_week=deltas_week, deltas_month=deltas_month,
            week_period=week_period, month_period=month_period,
        )
        if result:
            report_files.append(result)

    # ── 소명 요청 우선순위 생성 ───────────────────────────────
    prog(97, "소명 근거 생성 중...")
    from reports.justification_builder import build_justification_list
    justification_items = build_justification_list(filtered)

    elapsed = time.time() - start_time
    prog(100, "분석 완료!")

    return {
        'summaries':            filtered,
        'report_files':         report_files,
        'total_events':         len(all_events),
        'total_lines':          total_lines,
        'elapsed':              elapsed,
        'deltas_week':          deltas_week,
        'deltas_month':         deltas_month,
        'week_period':          week_period,
        'month_period':         month_period,
        'check_misuse':         check_misuse,
        'check_excess':         check_excess,
        'justification_items':  justification_items,
    }


def resolve_files(patterns: list[str]) -> list[str]:
    """glob 패턴을 실제 파일 경로 목록으로 확장합니다."""
    resolved = []
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            resolved.extend(matches)
        elif os.path.isfile(pattern):
            resolved.append(pattern)
    return sorted(set(resolved))
