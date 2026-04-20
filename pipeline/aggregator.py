"""
이벤트와 Finding을 사용자별로 집계하여 UserSummary를 생성합니다.
"""
from __future__ import annotations
import hashlib
from collections import defaultdict
from models.log_event import LogEvent
from models.finding import Finding
from models.user_summary import UserSummary
from detectors.access_counter import AccessCounter


def build_user_summaries(
    events: list[LogEvent],
    pii_findings: list[Finding],
    access_counter: AccessCounter,
) -> list[UserSummary]:
    """
    이벤트 목록과 Finding 목록으로부터 사용자별 요약을 생성합니다.
    """
    # 사용자별 이벤트 집계
    user_events: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        uid = event.user_id or 'UNKNOWN'
        user_events[uid].append(event)

    # 사용자별 PII Finding 집계
    user_pii_findings: dict[str, list[Finding]] = defaultdict(list)
    for finding in pii_findings:
        user_pii_findings[finding.user_id].append(finding)

    # 접근 카운터 Finding 집계
    user_access_findings: dict[str, list[Finding]] = defaultdict(list)
    for finding in access_counter.findings:
        user_access_findings[finding.user_id].append(finding)

    # 모든 사용자 ID 수집
    all_user_ids = set(user_events.keys()) | set(user_pii_findings.keys()) | set(user_access_findings.keys())

    summaries = []
    for user_id in all_user_ids:
        events_for_user = user_events.get(user_id, [])
        pii_events = [e for e in events_for_user if e.has_pii]

        # 접근 통계
        stats = access_counter.get_user_stats(user_id)

        # PII 유형 집계
        pii_types: set[str] = set()
        for event in pii_events:
            for hit in event.pii_hits:
                pii_types.add(hit.pii_type)

        # ── 쿼리 결과 기반 실효 노출량 집계 ───────────────────
        total_exposed = 0
        max_single = 0
        unknown_count = 0
        select_pii_count = 0
        search_only_count = 0

        for event in events_for_user:
            if event.exposure_type in ('FULL_EXPOSURE', 'PARTIAL_EXPOSURE'):
                select_pii_count += 1
                if event.effective_pii_exposure is None:
                    unknown_count += 1
                else:
                    total_exposed += event.effective_pii_exposure
                    max_single = max(max_single, event.effective_pii_exposure)
            elif event.exposure_type == 'SEARCH_ONLY':
                search_only_count += 1

        # 모든 Finding 합치기
        all_findings = user_pii_findings.get(user_id, []) + user_access_findings.get(user_id, [])
        all_findings.sort(key=lambda f: f.timestamp or __import__('datetime').datetime.min)

        summary = UserSummary(
            user_id=user_id,
            total_events=len(events_for_user),
            pii_event_count=len(pii_events),
            pii_types_seen=pii_types,
            max_queries_per_day=stats['max_queries_per_day'],
            max_queries_per_hour=stats['max_queries_per_hour'],
            peak_hour=stats['peak_hour'],
            peak_day=stats['peak_day'],
            after_hours_count=stats['after_hours_count'],
            bulk_export_count=stats['bulk_export_count'],
            unique_targets_per_day=stats['unique_targets_per_day'],
            findings=all_findings,
            total_pii_records_exposed=total_exposed,
            max_single_query_exposure=max_single,
            unknown_exposure_query_count=unknown_count,
            select_pii_query_count=select_pii_count,
            search_only_query_count=search_only_count,
        )
        summaries.append(summary)

    return summaries


def create_pii_finding_from_event(event: LogEvent) -> list[Finding]:
    """PII가 검출된 이벤트로부터 Finding 목록을 생성합니다."""
    findings = []
    for hit in event.pii_hits:
        finding_id = hashlib.sha256(
            f"{event.source_file}{event.line_no}{hit.pii_type}{hit.match_start}".encode()
        ).hexdigest()[:12]

        # 증적: 원본 값 + 컨텍스트 (마스킹 없음)
        full_text = event.query_text or event.raw_line
        original_value = full_text[hit.match_start:hit.match_end] if hit.match_end <= len(full_text) else hit.redacted_value
        context_text = full_text[:200]
        evidence = context_text[:hit.match_start] + f"[{hit.pii_type}:{original_value}]" + context_text[hit.match_end:]
        evidence = evidence[:300]

        # 실효 노출량에 따른 심각도 조정
        base_severity = hit.severity
        exposure = event.effective_pii_exposure
        if exposure is not None and exposure > 0:
            # 대량 노출 시 심각도 상향
            if exposure >= 20_000:
                base_severity = 'CRITICAL'
            elif exposure >= 5_000 and base_severity not in ('CRITICAL',):
                base_severity = 'HIGH'

        findings.append(Finding(
            finding_id=finding_id,
            category='PII_EXPOSURE',
            severity=base_severity,
            user_id=event.user_id or 'UNKNOWN',
            timestamp=event.timestamp,
            pii_types=[hit.pii_type],
            evidence=evidence,
            raw_reference=f"{event.source_file}:{event.line_no}",
            score=_severity_to_score(base_severity),
            details={
                'exposure_type': event.exposure_type,
                'result_row_count': event.result_row_count,
                'pii_select_fields': event.pii_select_fields,
                'effective_exposure': event.effective_pii_exposure,
                'is_select_star': event.is_select_star,
            },
        ))
    return findings


def _severity_to_score(severity: str) -> float:
    return {'CRITICAL': 10.0, 'HIGH': 7.0, 'MEDIUM': 4.0, 'LOW': 1.0}.get(severity, 0.0)
