"""
사용자별 일별 조회 건수 누적 관리
파일: <history_dir>/daily_counts.json
형식: {"user_id": {"YYYY-MM-DD": count, ...}, ...}
"""
from __future__ import annotations
import json
from datetime import date, timedelta
from pathlib import Path

_FILENAME = "daily_counts.json"
_RETENTION_DAYS = 35  # 30일 기준선 + 여유


def load_daily_counts(history_dir: Path) -> dict[str, dict[str, int]]:
    path = history_dir / _FILENAME
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return {}


def save_daily_counts(
    history_dir: Path,
    raw_daily_counts: dict[tuple, int],
) -> None:
    """
    AccessCounter._daily_counts를 누적 저장합니다.
    같은 날짜가 이미 있으면 덮어씁니다(최신 분석 우선).
    _RETENTION_DAYS일 이전 데이터는 자동 정리합니다.
    """
    history_dir.mkdir(parents=True, exist_ok=True)
    path = history_dir / _FILENAME

    existing = load_daily_counts(history_dir)

    for (uid, date_str), count in raw_daily_counts.items():
        if uid not in existing:
            existing[uid] = {}
        existing[uid][date_str] = count

    cutoff = str(date.today() - timedelta(days=_RETENTION_DAYS))
    for uid in existing:
        existing[uid] = {d: c for d, c in existing[uid].items() if d >= cutoff}

    path.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding='utf-8')
