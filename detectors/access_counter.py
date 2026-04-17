"""
과다조회 탐지 - 고정 윈도우 + 슬라이딩 윈도우 카운터
"""
from __future__ import annotations
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from models.log_event import LogEvent
from models.finding import Finding
from config import THRESHOLDS


class AccessCounter:
    """
    임직원별 접근 횟수를 추적하고 임계값 초과 시 Finding을 생성합니다.
    """

    def __init__(self):
        # 고정 윈도우: {(user_id, date_str): count}
        self._daily_counts: dict[tuple, int] = defaultdict(int)
        # 슬라이딩 윈도우: {user_id: deque[datetime]}
        self._hourly_windows: dict[str, deque] = defaultdict(deque)
        # 야간 조회: {(user_id, date_str): count}
        self._after_hours_counts: dict[tuple, int] = defaultdict(int)
        # 대량 조회: {(user_id, date_str): count}
        self._bulk_counts: dict[tuple, int] = defaultdict(int)
        # 고유 대상: {(user_id, date_str): set}
        self._unique_targets: dict[tuple, set] = defaultdict(set)
        # 피크 기록: {user_id: (peak_hour_str, peak_count)}
        self._hourly_peaks: dict[str, tuple] = {}
        self._daily_peaks: dict[str, tuple] = {}

        # 생성된 Finding 목록
        self.findings: list[Finding] = []
        # 이미 경고한 (user_id, window_key)를 추적 (중복 경고 방지)
        self._warned: set = set()

    def record(self, event: LogEvent) -> None:
        """이벤트를 기록하고 임계값 초과 시 Finding을 생성합니다."""
        user_id = event.user_id or 'UNKNOWN'
        ts = event.timestamp

        if ts is None:
            return

        date_str = ts.strftime('%Y-%m-%d')
        hour_str = ts.strftime('%Y-%m-%d %H:00')
        day_key = (user_id, date_str)
        hour_key = (user_id, hour_str)

        # ── 고정 윈도우 (일별) ──────────────────────────────
        self._daily_counts[day_key] += 1
        daily_count = self._daily_counts[day_key]

        # 피크 갱신
        if user_id not in self._daily_peaks or daily_count > self._daily_peaks[user_id][1]:
            self._daily_peaks[user_id] = (date_str, daily_count)

        if daily_count == THRESHOLDS['max_queries_per_day'] + 1:
            # 임계값 최초 초과 시점에만 경고
            warn_key = ('daily', user_id, date_str)
            if warn_key not in self._warned:
                self._warned.add(warn_key)
                severity = 'CRITICAL' if daily_count > THRESHOLDS['critical_queries_per_day'] else 'HIGH'
                self._add_finding(
                    category='EXCESSIVE_ACCESS',
                    severity=severity,
                    user_id=user_id,
                    timestamp=ts,
                    evidence=f"일별 조회 건수 {daily_count}건 (임계값: {THRESHOLDS['max_queries_per_day']}건)",
                    details={'window': 'daily', 'count': daily_count, 'date': date_str},
                    raw_reference=f"{event.source_file}:{event.line_no}",
                )

        # 임계값 이후에도 CRITICAL 조건 충족 시 업그레이드
        elif daily_count == THRESHOLDS['critical_queries_per_day'] + 1:
            warn_key = ('daily_critical', user_id, date_str)
            if warn_key not in self._warned:
                self._warned.add(warn_key)
                self._add_finding(
                    category='EXCESSIVE_ACCESS',
                    severity='CRITICAL',
                    user_id=user_id,
                    timestamp=ts,
                    evidence=f"일별 조회 건수 {daily_count}건 (위험 임계값: {THRESHOLDS['critical_queries_per_day']}건) - 즉각 조사 필요",
                    details={'window': 'daily_critical', 'count': daily_count, 'date': date_str},
                    raw_reference=f"{event.source_file}:{event.line_no}",
                )

        # ── 슬라이딩 윈도우 (시간당) ────────────────────────
        window = self._hourly_windows[user_id]
        # 1시간 초과 항목 제거
        cutoff = ts - timedelta(hours=1)
        while window and window[0] < cutoff:
            window.popleft()
        window.append(ts)
        hourly_count = len(window)

        # 피크 갱신
        if user_id not in self._hourly_peaks or hourly_count > self._hourly_peaks[user_id][1]:
            self._hourly_peaks[user_id] = (hour_str, hourly_count)

        if hourly_count == THRESHOLDS['max_queries_per_hour'] + 1:
            warn_key = ('hourly', user_id, hour_str)
            if warn_key not in self._warned:
                self._warned.add(warn_key)
                severity = 'CRITICAL' if hourly_count > THRESHOLDS['critical_queries_per_hour'] else 'HIGH'
                self._add_finding(
                    category='EXCESSIVE_ACCESS',
                    severity=severity,
                    user_id=user_id,
                    timestamp=ts,
                    evidence=f"1시간 내 조회 건수 {hourly_count}건 (임계값: {THRESHOLDS['max_queries_per_hour']}건/시간)",
                    details={'window': 'hourly', 'count': hourly_count, 'hour': hour_str},
                    raw_reference=f"{event.source_file}:{event.line_no}",
                )

        # ── 야간/업무 외 조회 ────────────────────────────────
        if event.has_pii:
            biz_start = THRESHOLDS['business_hours_start']
            biz_end = THRESHOLDS['business_hours_end']
            if not (biz_start <= ts.hour < biz_end):
                self._after_hours_counts[day_key] += 1
                after_count = self._after_hours_counts[day_key]
                if after_count == THRESHOLDS['after_hours_threshold'] + 1:
                    warn_key = ('after_hours', user_id, date_str)
                    if warn_key not in self._warned:
                        self._warned.add(warn_key)
                        self._add_finding(
                            category='AFTER_HOURS',
                            severity='HIGH',
                            user_id=user_id,
                            timestamp=ts,
                            evidence=f"업무 외 시간({ts.strftime('%H:%M')}) 개인정보 {after_count}건 조회",
                            details={'hour': ts.hour, 'count': after_count, 'date': date_str},
                            raw_reference=f"{event.source_file}:{event.line_no}",
                        )

        # ── 대량 조회 ────────────────────────────────────────
        if event.extra.get('is_bulk'):
            self._bulk_counts[day_key] += 1
            bulk_count = self._bulk_counts[day_key]
            if bulk_count > THRESHOLDS['bulk_export_per_day']:
                warn_key = ('bulk', user_id, date_str)
                if warn_key not in self._warned:
                    self._warned.add(warn_key)
                    self._add_finding(
                        category='BULK_EXPORT',
                        severity='HIGH',
                        user_id=user_id,
                        timestamp=ts,
                        evidence=f"하루 대량 조회 {bulk_count}건 (임계값: {THRESHOLDS['bulk_export_per_day']}건)",
                        details={'count': bulk_count, 'date': date_str},
                        raw_reference=f"{event.source_file}:{event.line_no}",
                    )

        # ── 실효 노출량 임계값 탐지 ──────────────────────────
        if event.effective_pii_exposure and event.effective_pii_exposure > 0:
            # 단일 쿼리 대량 노출
            single_high = THRESHOLDS.get('pii_single_query_high', 5_000)
            single_crit = THRESHOLDS.get('pii_single_query_critical', 20_000)
            exposure = event.effective_pii_exposure

            if exposure >= single_crit:
                warn_key = ('single_exposure_critical', user_id, date_str, event.line_no)
                if warn_key not in self._warned:
                    self._warned.add(warn_key)
                    self._add_finding(
                        category='PII_RECORD_EXPOSURE',
                        severity='CRITICAL',
                        user_id=user_id,
                        timestamp=ts,
                        evidence=(
                            f"단일 쿼리 개인정보 {exposure:,}건 노출 "
                            f"(PII필드 {event.pii_select_count}개 × 결과 {event.result_row_count:,}건)"
                        ),
                        details={
                            'exposure': exposure,
                            'result_rows': event.result_row_count,
                            'pii_fields': event.pii_select_fields,
                            'is_select_star': event.is_select_star,
                        },
                        raw_reference=f"{event.source_file}:{event.line_no}",
                    )
            elif exposure >= single_high:
                warn_key = ('single_exposure_high', user_id, date_str, event.line_no)
                if warn_key not in self._warned:
                    self._warned.add(warn_key)
                    self._add_finding(
                        category='PII_RECORD_EXPOSURE',
                        severity='HIGH',
                        user_id=user_id,
                        timestamp=ts,
                        evidence=(
                            f"단일 쿼리 개인정보 {exposure:,}건 노출 "
                            f"(PII필드 {event.pii_select_count}개 × 결과 {event.result_row_count:,}건)"
                        ),
                        details={
                            'exposure': exposure,
                            'result_rows': event.result_row_count,
                            'pii_fields': event.pii_select_fields,
                        },
                        raw_reference=f"{event.source_file}:{event.line_no}",
                    )

        # ── 고유 대상 다양성 ─────────────────────────────────
        if event.target:
            self._unique_targets[day_key].add(event.target)
            unique_count = len(self._unique_targets[day_key])
            if unique_count == THRESHOLDS['unique_targets_per_day'] + 1:
                warn_key = ('unique_targets', user_id, date_str)
                if warn_key not in self._warned:
                    self._warned.add(warn_key)
                    self._add_finding(
                        category='EXCESSIVE_ACCESS',
                        severity='MEDIUM',
                        user_id=user_id,
                        timestamp=ts,
                        evidence=f"하루 고유 대상 {unique_count}개 접근 (임계값: {THRESHOLDS['unique_targets_per_day']}개)",
                        details={'unique_targets': unique_count, 'date': date_str},
                        raw_reference=f"{event.source_file}:{event.line_no}",
                    )

    def get_user_stats(self, user_id: str) -> dict:
        """특정 사용자의 통계를 반환합니다."""
        max_daily = max(
            (v for (u, d), v in self._daily_counts.items() if u == user_id),
            default=0
        )
        max_hourly = self._hourly_peaks.get(user_id, ('', 0))[1]
        peak_hour = self._hourly_peaks.get(user_id, ('', 0))[0]
        peak_day = self._daily_peaks.get(user_id, ('', 0))[0]

        after_hours = sum(
            v for (u, d), v in self._after_hours_counts.items() if u == user_id
        )
        bulk_count = sum(
            v for (u, d), v in self._bulk_counts.items() if u == user_id
        )
        unique_targets = max(
            (len(v) for (u, d), v in self._unique_targets.items() if u == user_id),
            default=0
        )

        return {
            'max_queries_per_day': max_daily,
            'max_queries_per_hour': max_hourly,
            'peak_hour': peak_hour,
            'peak_day': peak_day,
            'after_hours_count': after_hours,
            'bulk_export_count': bulk_count,
            'unique_targets_per_day': unique_targets,
        }

    def _add_finding(self, **kwargs) -> None:
        finding_id = hashlib.sha256(
            f"{kwargs.get('user_id')}{kwargs.get('raw_reference', '')}{kwargs.get('category')}".encode()
        ).hexdigest()[:12]

        self.findings.append(Finding(
            finding_id=finding_id,
            category=kwargs['category'],
            severity=kwargs['severity'],
            user_id=kwargs['user_id'],
            timestamp=kwargs.get('timestamp'),
            evidence=kwargs.get('evidence', ''),
            raw_reference=kwargs.get('raw_reference', ''),
            details=kwargs.get('details', {}),
        ))
