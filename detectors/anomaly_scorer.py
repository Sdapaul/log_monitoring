"""
위험 점수 산정 엔진
각 사용자의 PII 접촉, 과다조회, 야간조회, 대량조회를 종합하여 0-100점 위험 점수를 산출합니다.
"""
from __future__ import annotations
from models.user_summary import UserSummary
from config import THRESHOLDS


def compute_risk_score(summary: UserSummary) -> tuple[float, str]:
    """
    UserSummary를 기반으로 위험 점수(0-100)와 등급을 반환합니다.

    점수 구성 (합계 100점):
      PII 접촉 점수       : 0-25점  (CRITICAL/HIGH Finding 수 기반)
      실효 노출량 점수    : 0-30점  (결과건수 × PII필드수) ← 신규
      과다조회 점수       : 0-20점  (일별/시간별 임계값 초과 비율)
      행동 이상 점수      : 0-25점  (야간·대량·다양성)

    Returns: (score, level) where level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    """
    # ── PII 접촉 점수 (0-25점) ────────────────────────────
    critical_pii = summary.critical_finding_count
    high_pii = summary.high_finding_count
    pii_score = min(25.0, critical_pii * 4.0 + high_pii * 1.5)

    # ── 실효 노출량 점수 (0-30점) ─────────────────────────
    # 실제로 화면에 노출된 개인정보 건수 기반
    exp_medium   = THRESHOLDS.get('pii_exposure_medium',   1_000)
    exp_high     = THRESHOLDS.get('pii_exposure_high',    10_000)
    exp_critical = THRESHOLDS.get('pii_exposure_critical', 50_000)
    exposed = summary.total_pii_records_exposed

    if exposed >= exp_critical:
        exposure_score = 30.0
    elif exposed >= exp_high:
        ratio = (exposed - exp_high) / max(exp_critical - exp_high, 1)
        exposure_score = 15.0 + ratio * 15.0
    elif exposed >= exp_medium:
        ratio = (exposed - exp_medium) / max(exp_high - exp_medium, 1)
        exposure_score = 5.0 + ratio * 10.0
    else:
        exposure_score = min(5.0, exposed / max(exp_medium, 1) * 5.0)

    # 단일 쿼리 대량 노출 보정
    single_high = THRESHOLDS.get('pii_single_query_high', 5_000)
    single_crit = THRESHOLDS.get('pii_single_query_critical', 20_000)
    if summary.max_single_query_exposure >= single_crit:
        exposure_score = max(exposure_score, 25.0)
    elif summary.max_single_query_exposure >= single_high:
        exposure_score = max(exposure_score, 15.0)

    exposure_score = min(30.0, exposure_score)

    # ── 과다조회 점수 (0-20점) ────────────────────────────
    max_day_threshold  = THRESHOLDS['max_queries_per_day']
    max_hour_threshold = THRESHOLDS['max_queries_per_hour']
    day_ratio  = summary.max_queries_per_day  / max_day_threshold  if max_day_threshold  > 0 else 0
    hour_ratio = summary.max_queries_per_hour / max_hour_threshold if max_hour_threshold > 0 else 0
    excess_score = min(20.0, day_ratio * 12.0 + hour_ratio * 8.0)

    # ── 행동 이상 점수 (0-25점) ───────────────────────────
    after_threshold = THRESHOLDS['after_hours_threshold']
    after_score = min(10.0, (summary.after_hours_count / max(after_threshold, 1)) * 10.0)

    bulk_threshold = THRESHOLDS['bulk_export_per_day']
    bulk_score = min(10.0, (summary.bulk_export_count / max(bulk_threshold, 1)) * 10.0)

    unique_threshold = THRESHOLDS['unique_targets_per_day']
    diversity_score = min(5.0, (summary.unique_targets_per_day / max(unique_threshold, 1)) * 5.0)

    total = pii_score + exposure_score + excess_score + after_score + bulk_score + diversity_score
    total = min(100.0, total)

    # 위험 등급 결정
    if total >= 70:
        level = 'CRITICAL'
    elif total >= 45:
        level = 'HIGH'
    elif total >= 20:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    # 강제 상향: 대량 실효 노출 발생 시 최소 HIGH 보장
    if exposed >= exp_high and level == 'MEDIUM':
        level = 'HIGH'
    if exposed >= exp_critical and level != 'CRITICAL':
        level = 'CRITICAL'

    # 강제 상향: 개별 Finding 심각도 반영 (HIGH 건 있으면 최소 HIGH, CRITICAL 건 있으면 최소 CRITICAL)
    if summary.high_finding_count > 0 and level in ('LOW', 'MEDIUM'):
        level = 'HIGH'
    if summary.critical_finding_count > 0 and level != 'CRITICAL':
        level = 'CRITICAL'

    return round(total, 2), level


def score_all(summaries: list[UserSummary]) -> list[UserSummary]:
    """모든 사용자 요약에 위험 점수를 적용하고 정렬합니다."""
    for summary in summaries:
        summary.risk_score, summary.risk_level = compute_risk_score(summary)

    # 위험 점수 내림차순 정렬
    summaries.sort(key=lambda s: s.risk_score, reverse=True)
    return summaries
