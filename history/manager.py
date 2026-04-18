"""
분석 이력 관리 모듈
- 매 분석 실행 결과를 JSON으로 저장
- 이전 주/이전 달 동기간 스냅샷 조회
- 사용자별 변화량(delta) 계산
"""
from __future__ import annotations
import json
from datetime import datetime, date
from pathlib import Path
from models.user_summary import UserSummary


# 저장할 필드 목록 (비교 의미 있는 수치형 필드만)
COMPARABLE_FIELDS = [
    'risk_score',
    'pii_event_count',
    'total_events',
    'max_queries_per_day',
    'max_queries_per_hour',
    'after_hours_count',
    'bulk_export_count',
    'flagged_event_count',
    'total_pii_records_exposed',
    'max_single_query_exposure',
    'risk_level',
    'pii_types_str',
]


def _summary_to_dict(s: UserSummary) -> dict:
    return {
        'risk_score': s.risk_score,
        'risk_level': s.risk_level,
        'pii_event_count': s.pii_event_count,
        'total_events': s.total_events,
        'max_queries_per_day': s.max_queries_per_day,
        'max_queries_per_hour': s.max_queries_per_hour,
        'after_hours_count': s.after_hours_count,
        'bulk_export_count': s.bulk_export_count,
        'flagged_event_count': s.flagged_event_count,  # property → int
        'total_pii_records_exposed': s.total_pii_records_exposed,
        'max_single_query_exposure': s.max_single_query_exposure,
        'pii_types_str': s.pii_types_str,
    }


def save_snapshot(
    history_dir: Path,
    start_date: date,
    end_date: date,
    summaries: list[UserSummary],
    total_events: int = 0,
    total_lines: int = 0,
) -> Path:
    """
    현재 분석 결과를 JSON 스냅샷으로 저장합니다.
    파일명: STARTDATE_ENDDATE_YYYYMMDD_HHMMSS.json
    """
    history_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{start_date}_{end_date}_{ts}.json"
    path = history_dir / filename

    period_days = (end_date - start_date).days + 1
    data = {
        'meta': {
            'start_date': str(start_date),
            'end_date': str(end_date),
            'period_days': period_days,
            'saved_at': datetime.now().isoformat(),
            'total_events': total_events,
            'total_lines': total_lines,
            'user_count': len(summaries),
        },
        'users': {
            s.user_id: _summary_to_dict(s) for s in summaries
        }
    }

    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"  [이력 저장] {filename}")
    return path


def find_snapshot(
    history_dir: Path,
    target_start: date,
    target_end: date,
) -> dict:
    """
    지정한 기간에 해당하는 가장 최근 스냅샷을 찾아 반환합니다.
    기간 길이(period_days)와 날짜가 정확히 일치해야 합니다.
    Returns: {user_id: stats_dict} 또는 {}
    """
    if not history_dir.exists():
        return {}

    period_days = (target_end - target_start).days + 1
    best_data = None
    best_ts = ''

    for f in sorted(history_dir.glob('*.json')):
        try:
            raw = json.loads(f.read_text(encoding='utf-8'))
            m = raw.get('meta', {})
            if (m.get('start_date') == str(target_start)
                    and m.get('end_date') == str(target_end)
                    and m.get('period_days') == period_days):
                saved_at = m.get('saved_at', '')
                if saved_at > best_ts:
                    best_data = raw.get('users', {})
                    best_ts = saved_at
        except Exception:
            continue

    return best_data or {}


def find_closest_snapshot(
    history_dir: Path,
    target_start: date,
    target_end: date,
    tolerance_days: int = 3,
) -> tuple[dict, str]:
    """
    정확한 기간 매칭이 없을 때 허용 오차 내에서 가장 가까운 스냅샷을 찾습니다.
    Returns: ({user_id: stats_dict}, matched_period_str) 또는 ({}, '')
    """
    if not history_dir.exists():
        return {}, ''

    period_days = (target_end - target_start).days + 1
    best_data = None
    best_period = ''
    best_diff = float('inf')

    for f in sorted(history_dir.glob('*.json')):
        try:
            raw = json.loads(f.read_text(encoding='utf-8'))
            m = raw.get('meta', {})
            snap_start = date.fromisoformat(m['start_date'])
            snap_end = date.fromisoformat(m['end_date'])
            snap_days = m.get('period_days', 0)

            # 기간 길이 차이 허용
            if abs(snap_days - period_days) > tolerance_days:
                continue

            # 날짜 거리 계산
            start_diff = abs((snap_start - target_start).days)
            end_diff = abs((snap_end - target_end).days)
            total_diff = start_diff + end_diff

            if total_diff < best_diff:
                best_diff = total_diff
                best_data = raw.get('users', {})
                best_period = f"{snap_start} ~ {snap_end}"
        except Exception:
            continue

    return (best_data or {}), best_period


def compute_deltas(
    current_summaries: list[UserSummary],
    prior_users: dict,
) -> dict[str, dict]:
    """
    현재 기간과 이전 기간의 사용자별 변화량을 계산합니다.
    두 기간 모두 존재하는 사용자만 포함됩니다.
    Returns: {user_id: {field: delta, ...}}
    """
    NUMERIC_FIELDS = [
        'risk_score', 'pii_event_count', 'total_events',
        'max_queries_per_day', 'max_queries_per_hour',
        'after_hours_count', 'bulk_export_count', 'flagged_event_count',
        'total_pii_records_exposed', 'max_single_query_exposure',
    ]
    deltas = {}
    for s in current_summaries:
        prior = prior_users.get(s.user_id)
        if prior is None:
            continue
        current_dict = _summary_to_dict(s)
        user_delta = {}
        for field in NUMERIC_FIELDS:
            curr_val = current_dict.get(field, 0) or 0
            prev_val = prior.get(field, 0) or 0
            user_delta[field] = curr_val - prev_val
        # 등급 변화
        user_delta['risk_level_prev'] = prior.get('risk_level', '-')
        user_delta['pii_types_prev'] = prior.get('pii_types_str', '-')
        deltas[s.user_id] = user_delta
    return deltas


def trend_arrow(delta: float) -> str:
    """수치 변화량을 추세 문자로 변환합니다."""
    if delta > 0:
        return '↑'
    elif delta < 0:
        return '↓'
    return '→'


def trend_label(delta: float, field: str = 'risk_score') -> str:
    """
    위험 관련 필드: 증가=악화(↑), 감소=개선(↓)
    부호 포함 문자열 반환.
    """
    arrow = trend_arrow(delta)
    if isinstance(delta, float):
        return f"{arrow} {delta:+.1f}"
    return f"{arrow} {delta:+d}"


def list_all_snapshots(history_dir: Path) -> list[dict]:
    """저장된 모든 스냅샷 메타 정보를 반환합니다."""
    if not history_dir.exists():
        return []
    result = []
    for f in sorted(history_dir.glob('*.json'), reverse=True):
        try:
            raw = json.loads(f.read_text(encoding='utf-8'))
            meta = raw.get('meta', {})
            meta['filename'] = f.name
            result.append(meta)
        except Exception:
            continue
    return result
