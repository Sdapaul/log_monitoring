"""
HTML 보고서 생성기 - Bootstrap 5 + Chart.js + DataTables 기반
자체 완결형 HTML 파일로 생성됩니다.
"""
from __future__ import annotations
import json
from datetime import datetime, date
from pathlib import Path
from models.user_summary import UserSummary

# 폐쇄망 대응: static 폴더의 JS/CSS를 인라인으로 삽입
_STATIC_DIR = Path(__file__).parent.parent / 'static'

def _inline_css(*rel_paths: str) -> str:
    parts = []
    for p in rel_paths:
        f = _STATIC_DIR / p
        if f.exists():
            parts.append(f'<style>{f.read_text(encoding="utf-8")}</style>')
    return '\n'.join(parts)

def _inline_js(*rel_paths: str) -> str:
    parts = []
    for p in rel_paths:
        f = _STATIC_DIR / p
        if f.exists():
            parts.append(f'<script>{f.read_text(encoding="utf-8")}</script>')
    return '\n'.join(parts)


RISK_BADGE = {
    'CRITICAL': '<span class="badge bg-danger">최고위험</span>',
    'HIGH': '<span class="badge bg-warning text-dark">고위험</span>',
    'MEDIUM': '<span class="badge bg-info text-dark">중위험</span>',
    'LOW': '<span class="badge bg-success">저위험</span>',
}

RISK_ROW_CLASS = {
    'CRITICAL': 'table-danger',
    'HIGH': 'table-warning',
    'MEDIUM': 'table-info',
    'LOW': '',
}

CATEGORY_KR = {
    'PII_EXPOSURE': '개인정보 노출',
    'EXCESSIVE_ACCESS': '과다조회',
    'AFTER_HOURS': '업무외시간조회',
    'BULK_EXPORT': '대량조회',
}


def generate_html(
    summaries: list[UserSummary],
    start_date: date,
    end_date: date,
    output_path: str,
    total_events: int = 0,
    total_lines: int = 0,
    deltas_week: dict | None = None,
    deltas_month: dict | None = None,
    week_period: str = '',
    month_period: str = '',
) -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    report_ts = datetime.now()

    # 통계 계산
    stats = _compute_stats(summaries)

    # 소명 우선순위 생성
    from reports.justification_builder import build_justification_list
    just_items = build_justification_list(summaries)

    # 차트 데이터 준비
    risk_dist = {
        'CRITICAL': stats['critical_users'],
        'HIGH': stats['high_users'],
        'MEDIUM': stats['medium_users'],
        'LOW': stats['low_users'],
    }
    pii_type_counts = _compute_pii_type_counts(summaries)

    html = _build_html(
        summaries=summaries,
        start_date=start_date,
        end_date=end_date,
        report_ts=report_ts,
        total_events=total_events,
        total_lines=total_lines,
        stats=stats,
        risk_dist=risk_dist,
        pii_type_counts=pii_type_counts,
        deltas_week=deltas_week or {},
        deltas_month=deltas_month or {},
        week_period=week_period,
        month_period=month_period,
        just_items=just_items,
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path


def _compute_stats(summaries: list[UserSummary]) -> dict:
    return {
        'total_users': len(summaries),
        'critical_users': sum(1 for s in summaries if s.risk_level == 'CRITICAL'),
        'high_users': sum(1 for s in summaries if s.risk_level == 'HIGH'),
        'medium_users': sum(1 for s in summaries if s.risk_level == 'MEDIUM'),
        'low_users': sum(1 for s in summaries if s.risk_level == 'LOW'),
        'total_findings': sum(len(s.findings) for s in summaries),
        'pii_findings': sum(s.pii_finding_count for s in summaries),
        'excess_findings': sum(s.excess_finding_count for s in summaries),
        'total_pii_records_exposed': sum(s.total_pii_records_exposed for s in summaries),
        'max_single_query_exposure': max((s.max_single_query_exposure for s in summaries), default=0),
    }


def _compute_pii_type_counts(summaries: list[UserSummary]) -> dict:
    counts: dict[str, int] = {}
    for s in summaries:
        for pt in s.pii_types_seen:
            counts[pt] = counts.get(pt, 0) + 1
    return counts


def _trend_html(delta_val, label: str, is_risk: bool = True) -> str:
    """수치 변화량을 HTML 뱃지로 변환합니다."""
    if delta_val is None:
        return f'<span class="text-muted small">-</span>'
    if delta_val > 0:
        css = 'text-danger' if is_risk else 'text-primary'
        arrow = '↑'
    elif delta_val < 0:
        css = 'text-success' if is_risk else 'text-primary'
        arrow = '↓'
    else:
        css = 'text-muted'
        arrow = '→'

    if isinstance(delta_val, float):
        val_str = f"{delta_val:+.1f}"
    else:
        val_str = f"{delta_val:+d}"

    return f'<span class="{css} small" title="{label} 대비 {val_str}">{arrow}{val_str}</span>'


def _user_rows(
    summaries: list[UserSummary],
    deltas_week: dict | None = None,
    deltas_month: dict | None = None,
) -> str:
    rows = []
    dw_all = deltas_week or {}
    dm_all = deltas_month or {}
    has_history = bool(dw_all or dm_all)

    for s in summaries:
        rc = RISK_ROW_CLASS.get(s.risk_level, '')
        badge = RISK_BADGE.get(s.risk_level, s.risk_level)
        dw = dw_all.get(s.user_id, {})
        dm = dm_all.get(s.user_id, {})

        # 위험 점수 + 추세
        score_trend_w = _trend_html(dw.get('risk_score'), '1주 전')
        score_trend_m = _trend_html(dm.get('risk_score'), '1개월 전')
        score_cell = f"{s.risk_score:.1f}"
        if has_history:
            score_cell += f" / {score_trend_w}(주) / {score_trend_m}(월)"

        # PII 건수 + 추세
        pii_trend_w = _trend_html(dw.get('pii_event_count'), '1주 전') if has_history else ''
        pii_trend_m = _trend_html(dm.get('pii_event_count'), '1개월 전') if has_history else ''
        if has_history:
            pii_cell = f"{s.pii_event_count:,} / {pii_trend_w}(주) / {pii_trend_m}(월)"
        else:
            pii_cell = f"{s.pii_event_count:,}"

        # 신규 위험 상승 표시
        prev_level_w = dw.get('risk_level_prev', '')
        is_new_risk = (
            s.risk_level in ('HIGH', 'CRITICAL') and
            prev_level_w in ('LOW', 'MEDIUM')
        )
        new_risk_badge = ' <span class="badge bg-danger">NEW↑</span>' if is_new_risk else ''

        # PII 노출량 표시
        exposure_display = s.exposure_display if hasattr(s, 'exposure_display') else f"{s.total_pii_records_exposed:,}"
        exposure_risk = s.exposure_risk_level if hasattr(s, 'exposure_risk_level') else ''
        exp_css = {'HIGH': 'text-warning fw-bold', 'CRITICAL': 'text-danger fw-bold'}.get(exposure_risk, '')

        rows.append(f"""
        <tr class="{rc}">
            <td><strong>{s.user_id}</strong>{new_risk_badge}</td>
            <td>{s.total_events:,}</td>
            <td>{pii_cell}</td>
            <td>{s.pii_types_str}</td>
            <td class="{exp_css}">{exposure_display}</td>
            <td>{s.max_single_query_exposure:,}</td>
            <td>{s.max_queries_per_hour:,}</td>
            <td>{s.max_queries_per_day:,}</td>
            <td>{s.after_hours_count:,}</td>
            <td>{s.bulk_export_count:,}</td>
            <td><a href="#findingTable" class="finding-link text-decoration-none fw-bold" data-user="{s.user_id}" title="{s.user_id} 이상 징후 상세 보기">{s.flagged_event_count:,} 🔍</a></td>
            <td>{score_cell}</td>
            <td>{badge}</td>
        </tr>""")
    return '\n'.join(rows)


def _build_comparison_section(summaries: list[UserSummary], dw: dict, dm: dict) -> str:
    """기간별 위험 점수 변화 테이블 HTML을 생성합니다."""
    rows = []
    for s in summaries:
        uw = dw.get(s.user_id, {})
        um = dm.get(s.user_id, {})

        # 1주 전 점수
        d_score_w = uw.get('risk_score')
        prev_score_w = f"{s.risk_score - d_score_w:.1f}" if d_score_w is not None else '-'
        trend_w = _trend_html(d_score_w, '1주 전')

        # 1개월 전 점수
        d_score_m = um.get('risk_score')
        prev_score_m = f"{s.risk_score - d_score_m:.1f}" if d_score_m is not None else '-'
        trend_m = _trend_html(d_score_m, '1개월 전')

        # PII 변화
        pii_trend_w = _trend_html(uw.get('pii_event_count'), '1주 전')
        pii_trend_m = _trend_html(um.get('pii_event_count'), '1개월 전')

        # 신규 위험 상승 여부
        prev_level = uw.get('risk_level_prev', '') or um.get('risk_level_prev', '')
        is_new = s.risk_level in ('HIGH', 'CRITICAL') and prev_level in ('LOW', 'MEDIUM')
        new_badge = '<span class="badge bg-danger">NEW↑</span>' if is_new else '-'

        rc = RISK_ROW_CLASS.get(s.risk_level, '')
        badge = RISK_BADGE.get(s.risk_level, s.risk_level)

        rows.append(f"""
        <tr class="{rc}">
          <td><strong>{s.user_id}</strong></td>
          <td>{s.risk_score:.1f}</td>
          <td>{prev_score_w}</td>
          <td>{trend_w}</td>
          <td>{prev_score_m}</td>
          <td>{trend_m}</td>
          <td>{pii_trend_w}</td>
          <td>{pii_trend_m}</td>
          <td>{badge}</td>
          <td>{new_badge}</td>
        </tr>""")

    rows_html = '\n'.join(rows)
    return f"""
  <h5 class="section-title">기간별 위험 점수 변화 비교</h5>
  <div class="card mb-4">
    <div class="card-body table-responsive">
      <table id="compTable" class="table table-sm table-hover table-bordered">
        <thead>
          <tr>
            <th>사원ID</th><th>현재점수</th><th>1주전점수</th><th>점수변화(주)</th>
            <th>1개월전점수</th><th>점수변화(월)</th><th>PII변화(주)</th><th>PII변화(월)</th>
            <th>현재등급</th><th>신규상승</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
  </div>"""


def _finding_rows(summaries: list[UserSummary]) -> str:
    rows = []
    count = 0
    for s in summaries:
        for f in s.findings:
            if count >= 5000:
                rows.append('<tr><td colspan="7" class="text-muted text-center">이하 생략 (상위 5,000건만 표시)</td></tr>')
                return '\n'.join(rows)
            badge = RISK_BADGE.get(s.risk_level, s.risk_level)
            cat_kr = CATEGORY_KR.get(f.category, f.category)
            evidence = (f.evidence or '')[:200].replace('<', '&lt;').replace('>', '&gt;')
            rows.append(f"""
            <tr>
                <td>{f.user_id}</td>
                <td>{f.timestamp_str}</td>
                <td>{cat_kr}</td>
                <td>{f.pii_types_str}</td>
                <td>{badge}</td>
                <td><small class="text-muted">{evidence}</small></td>
                <td><small>{f.raw_reference}</small></td>
            </tr>""")
            count += 1
    return '\n'.join(rows)


def _build_justification_section(just_items: list) -> str:
    """소명 요청 우선순위 섹션 HTML을 생성합니다."""
    if not just_items:
        return ''

    URGENCY_STYLE = {
        '즉시': 'background:#6F0000;color:white',
        '긴급': 'background:#8B4513;color:white',
        '검토': 'background:#1F4E79;color:white',
    }

    cards = []
    for item in just_items:
        urg_style = URGENCY_STYLE.get(item.urgency, 'background:#1F4E79;color:white')
        reasons_html = ''.join(f'<li>{r}</li>' for r in item.reasons)
        questions_html = ''.join(f'<li>{q}</li>' for q in item.questions[:3])

        # key findings (top 3)
        findings_html = ''
        for kf in item.key_findings[:3]:
            sev_badge = {'CRITICAL': 'danger', 'HIGH': 'warning'}.get(kf.get('severity', ''), 'secondary')
            evidence = (kf.get('evidence') or '')[:120]
            findings_html += f'<tr><td>{kf.get("timestamp","")}</td><td><span class="badge bg-{sev_badge}">{kf.get("category_kr","")}</span></td><td><small>{evidence}</small></td></tr>'

        cards.append(f"""
  <div class="card mb-3 border-0 shadow-sm">
    <div class="card-header py-2 d-flex align-items-center gap-2" style="{urg_style}">
      <strong>#{item.priority_rank} {item.user_id}</strong>
      <span class="badge bg-light text-dark">{item.urgency}</span>
      <span class="ms-auto small">위험점수: {item.risk_score:.1f} | 소명우선도: {item.priority_score:.0f}점</span>
    </div>
    <div class="card-body py-2">
      <p class="mb-1 fw-bold">{item.summary_one_line}</p>
      <strong>위반 사유:</strong>
      <ul class="mb-2 ps-3">{''.join(f'<li>{r}</li>' for r in item.reasons)}</ul>
      <strong>화면 추정 노출:</strong>
      <p class="text-muted small mb-2">{item.screen_estimate}</p>
      {'<strong>핵심 증적 (상위 3건):</strong><table class="table table-sm table-bordered mt-1"><thead><tr><th>일시</th><th>유형</th><th>증적</th></tr></thead><tbody>' + findings_html + '</tbody></table>' if findings_html else ''}
      <strong>소명 질문 (상위 3개):</strong>
      <ol class="mb-0 ps-3">{''.join(f'<li>{q}</li>' for q in item.questions[:3])}</ol>
    </div>
  </div>""")

    cards_html = '\n'.join(cards)
    return f"""
  <h5 class="section-title" style="color:#8B0000">소명 요청 우선순위 (MEDIUM 이상 대상)</h5>
  <div class="alert alert-danger py-2 mb-3 small">
    <strong>소명 요청 순서:</strong> 아래 순위는 위험도가 아닌 <em>즉각 확인 필요성</em>(단일 대량 노출, 야간 접근, 과다조회 등)을 기준으로 자동 산정됩니다.
    소명 요청 시 핵심 증적을 첨부하고, 화면 추정 노출 내용을 설명한 뒤 질문 목록을 전달하십시오.
  </div>
  {cards_html}"""


def _build_html(summaries, start_date, end_date, report_ts, total_events, total_lines,
                stats, risk_dist, pii_type_counts,
                deltas_week=None, deltas_month=None,
                week_period='', month_period='',
                just_items=None) -> str:
    dw = deltas_week or {}
    dm = deltas_month or {}
    user_rows_html = _user_rows(summaries, deltas_week=dw, deltas_month=dm)
    finding_rows_html = _finding_rows(summaries)
    has_history = bool(dw or dm)
    comparison_section_html = _build_comparison_section(summaries, dw, dm) if has_history else ''
    justification_section_html = _build_justification_section(just_items or [])
    trend_legend_html = (
        f'<div class="alert alert-info py-2 mb-2 small">'
        f'<strong>분석 기간:</strong> <span class="fw-bold text-dark">{start_date} ~ {end_date}</span>'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;'
        f'<strong>추세 기호:</strong> &nbsp;↑ 증가(위험 상승) &nbsp;↓ 감소(위험 개선) &nbsp;→ 변화없음'
        f'&nbsp;| &nbsp;<span class="badge bg-danger">NEW↑</span> 신규 위험 등급 상승'
        f'&nbsp;| &nbsp;주 비교기간={week_period or "이력 없음"} &nbsp; 월 비교기간={month_period or "이력 없음"}'
        f'</div>'
    ) if has_history else (
        f'<div class="alert alert-info py-2 mb-2 small">'
        f'<strong>분석 기간:</strong> <span class="fw-bold text-dark">{start_date} ~ {end_date}</span>'
        f'&nbsp;&nbsp;|&nbsp;&nbsp;이전 이력 없음 (추세 비교 불가)'
        f'</div>'
    )

    inline_css_html = _inline_css('css/bootstrap.min.css', 'css/dataTables.bootstrap5.min.css')
    inline_js_html = _inline_js('js/jquery.min.js', 'js/bootstrap.bundle.min.js',
                                'js/jquery.dataTables.min.js', 'js/dataTables.bootstrap5.min.js',
                                'js/chart.umd.min.js')

    risk_labels = json.dumps(['최고위험(CRITICAL)', '고위험(HIGH)', '중위험(MEDIUM)', '저위험(LOW)'])
    risk_data = json.dumps([risk_dist['CRITICAL'], risk_dist['HIGH'], risk_dist['MEDIUM'], risk_dist['LOW']])
    risk_colors = json.dumps(['#dc3545', '#fd7e14', '#17a2b8', '#28a745'])

    pii_labels = json.dumps(list(pii_type_counts.keys()))
    pii_data = json.dumps(list(pii_type_counts.values()))

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>개인정보 오남용·과다조회 점검 보고서</title>
{inline_css_html}
<style>
  body {{ font-family: '맑은 고딕', 'Malgun Gothic', sans-serif; background: #f8f9fa; }}
  .report-header {{ background: linear-gradient(135deg, #1F4E79 0%, #2E75B6 100%); color: white; padding: 2rem; border-radius: 8px; margin-bottom: 1.5rem; }}
  .stat-card {{ border-left: 4px solid; border-radius: 6px; }}
  .stat-critical {{ border-left-color: #dc3545; }}
  .stat-high {{ border-left-color: #fd7e14; }}
  .stat-medium {{ border-left-color: #17a2b8; }}
  .stat-low {{ border-left-color: #28a745; }}
  .chart-container {{ height: 280px; }}
  .section-title {{ border-bottom: 2px solid #1F4E79; padding-bottom: 8px; color: #1F4E79; font-weight: bold; margin: 1.5rem 0 1rem; }}
  .table th {{ background-color: #1F4E79; color: white; white-space: nowrap; }}
  .badge {{ font-size: 0.8em; }}
  @media print {{ .no-print {{ display: none; }} }}
</style>
</head>
<body>
<div class="container-fluid py-4">

  <!-- 헤더 -->
  <div class="report-header">
    <h2 class="mb-1">🔍 개인정보 오남용·과다조회 점검 보고서</h2>
    <div class="d-flex gap-4 mt-2 flex-wrap">
      <span>📅 분석 기간: <strong>{start_date} ~ {end_date}</strong></span>
      <span>🕐 생성 일시: <strong>{report_ts.strftime('%Y-%m-%d %H:%M:%S')}</strong></span>
      <span>📊 총 분석 이벤트: <strong>{total_events:,}건</strong></span>
      <span>📄 총 로그 라인: <strong>{total_lines:,}줄</strong></span>
    </div>
  </div>

  <!-- 요약 카드 -->
  <div class="row g-3 mb-4">
    <div class="col-md-2">
      <div class="card stat-card stat-critical h-100">
        <div class="card-body text-center">
          <div class="fs-1 fw-bold text-danger">{stats['critical_users']}</div>
          <div class="text-muted">최고위험(CRITICAL) 사용자</div>
        </div>
      </div>
    </div>
    <div class="col-md-2">
      <div class="card stat-card stat-high h-100">
        <div class="card-body text-center">
          <div class="fs-1 fw-bold text-warning">{stats['high_users']}</div>
          <div class="text-muted">고위험(HIGH) 사용자</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card stat-medium h-100">
        <div class="card-body text-center">
          <div class="fs-1 fw-bold text-info">{stats['total_findings']}</div>
          <div class="text-muted">총 이상 징후 건수</div>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card stat-critical h-100">
        <div class="card-body text-center">
          <div class="fs-2 fw-bold text-danger">{stats['total_pii_records_exposed']:,}</div>
          <div class="text-muted">PII 노출 레코드 수 (합계)</div>
          <div class="small text-muted">단일쿼리 최대: {stats['max_single_query_exposure']:,}건</div>
        </div>
      </div>
    </div>
    <div class="col-md-2">
      <div class="card stat-card stat-low h-100">
        <div class="card-body text-center">
          <div class="fs-1 fw-bold text-success">{stats['total_users']}</div>
          <div class="text-muted">총 분석 사용자 수</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 차트 -->
  <div class="row g-3 mb-4">
    <div class="col-md-6">
      <div class="card h-100">
        <div class="card-header fw-bold">위험 등급 분포</div>
        <div class="card-body"><canvas id="riskChart" class="chart-container"></canvas></div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card h-100">
        <div class="card-header fw-bold">개인정보 유형별 검출 현황</div>
        <div class="card-body"><canvas id="piiChart" class="chart-container"></canvas></div>
      </div>
    </div>
  </div>

  <!-- 소명 요청 우선순위 -->
  {justification_section_html}

  <!-- 사용자별 현황 테이블 -->
  <h5 class="section-title">사용자별 점검 현황</h5>
  {trend_legend_html}
  <div class="card mb-4">
    <div class="card-body table-responsive">
      <table id="userTable" class="table table-sm table-hover table-bordered">
        <thead>
          <tr>
            <th>사원ID</th><th>총조회수</th>
            <th title="개인정보(PII)가 사용된 쿼리 건수 / 전주 대비 / 전월 대비">PII쿼리수 (주↑/월↑)</th>
            <th>PII유형</th>
            <th title="쿼리 결과에 개인정보가 출력된 건수. 0건=출력건수 0으로 확인, 미상N건=결과건수 미확인 쿼리 N개">PII출력건수</th>
            <th title="단일 쿼리에서 최대로 출력된 PII 레코드 수">단일쿼리최대출력</th>
            <th>최대/시간</th><th>최대/일</th><th>야간조회</th><th>대량조회</th>
            <th>이상건수</th><th>위험점수 (↑주/↑월)</th><th>등급</th>
          </tr>
        </thead>
        <tbody>
          {user_rows_html}
        </tbody>
      </table>
    </div>
  </div>

  <!-- 이상 징후 상세 -->
  <h5 class="section-title">이상 징후 상세 내역</h5>
  <div class="card mb-4">
    <div class="card-body table-responsive">
      <table id="findingTable" class="table table-sm table-hover table-bordered">
        <thead>
          <tr>
            <th>사원ID</th><th>일시</th><th>유형</th><th>PII유형</th>
            <th>위험등급</th><th>증적</th><th>소스:라인</th>
          </tr>
        </thead>
        <tbody>
          {finding_rows_html}
        </tbody>
      </table>
    </div>
  </div>

  {comparison_section_html}

  <!-- 위험 등급 기준 -->
  <h5 class="section-title">위험 등급 기준</h5>
  <div class="card mb-4">
    <div class="card-body">
      <table class="table table-bordered table-sm">
        <thead><tr><th>등급</th><th>점수</th><th>조치 기준</th></tr></thead>
        <tbody>
          <tr class="table-danger"><td><strong>CRITICAL (최고위험)</strong></td><td>70-100점</td><td>즉각 조사 및 소명 요청, 접근 권한 즉시 검토</td></tr>
          <tr class="table-warning"><td><strong>HIGH (고위험)</strong></td><td>45-69점</td><td>소명 요청 및 모니터링 강화, 접근 이력 검토</td></tr>
          <tr class="table-info"><td><strong>MEDIUM (중위험)</strong></td><td>20-44점</td><td>주의 조치 및 개인정보 보호 교육 실시</td></tr>
          <tr><td><strong>LOW (저위험)</strong></td><td>0-19점</td><td>정상 범위, 정기 모니터링 유지</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="text-muted text-center pb-3">
    <small>본 보고서는 개인정보보호법 및 내부 보안 정책에 따라 생성되었습니다. | 생성: {report_ts.strftime('%Y-%m-%d %H:%M:%S')}</small>
  </div>
</div>

<!-- Scripts (인라인 삽입 - 폐쇄망 대응) -->
{inline_js_html}
<script>
$(document).ready(function() {{
  $('#userTable').DataTable({{
    pageLength: 25, order: [[9, 'desc']],
    language: {{ search: '검색:', lengthMenu: '_MENU_ 행 표시', info: '_START_-_END_ / _TOTAL_ 건', paginate: {{ first:'처음', last:'끝', next:'다음', previous:'이전' }} }}
  }});
  var findingDT = $('#findingTable').DataTable({{
    pageLength: 25,
    language: {{ search: '검색:', lengthMenu: '_MENU_ 행 표시', info: '_START_-_END_ / _TOTAL_ 건', paginate: {{ first:'처음', last:'끝', next:'다음', previous:'이전' }} }}
  }});

  // 이상건수 클릭 -> 이상 징후 상세 테이블을 해당 사용자로 필터링
  $(document).on('click', '.finding-link', function(e) {{
    var userId = $(this).data('user');
    findingDT.search(userId).draw();
    // 이미 해당 사용자로 검색 중이면 클릭 시 전체 초기화
    var $label = $('#findingFilterLabel');
    if (!$label.length) {{
      $('<div id="findingFilterLabel" class="alert alert-warning py-1 px-3 mb-2 small d-flex justify-content-between align-items-center">'
        + '<span>필터: <strong class="filter-user-id"></strong> 의 이상 징후만 표시중</span>'
        + '<button class="btn btn-sm btn-outline-secondary ms-3" id="clearFindingFilter">전체 보기</button>'
        + '</div>').insertBefore('#findingTable_wrapper');
    }}
    $('#findingFilterLabel .filter-user-id').text(userId);
    $('#findingFilterLabel').show();
  }});

  $(document).on('click', '#clearFindingFilter', function() {{
    findingDT.search('').draw();
    $('#findingFilterLabel').hide();
  }});

  if ($('#compTable').length) {{
    $('#compTable').DataTable({{
      pageLength: 25, order: [[1, 'desc']],
      language: {{ search: '검색:', lengthMenu: '_MENU_ 행 표시', info: '_START_-_END_ / _TOTAL_ 건', paginate: {{ first:'처음', last:'끝', next:'다음', previous:'이전' }} }}
    }});
  }}

  // 위험 등급 분포 차트
  new Chart(document.getElementById('riskChart'), {{
    type: 'bar',
    data: {{ labels: {risk_labels}, datasets: [{{ label: '사용자 수', data: {risk_data}, backgroundColor: {risk_colors} }}] }},
    options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }} }}
  }});

  // PII 유형 분포 차트
  const piiLabels = {pii_labels};
  const piiData = {pii_data};
  if (piiLabels.length > 0) {{
    new Chart(document.getElementById('piiChart'), {{
      type: 'doughnut',
      data: {{ labels: piiLabels, datasets: [{{ data: piiData, backgroundColor: ['#dc3545','#fd7e14','#ffc107','#17a2b8','#6f42c1','#20c997','#6610f2','#e83e8c','#fd7e14','#28a745'] }}] }},
      options: {{ responsive: true, maintainAspectRatio: false }}
    }});
  }} else {{
    document.getElementById('piiChart').parentElement.innerHTML = '<p class="text-center text-muted mt-5">개인정보 검출 없음</p>';
  }}
}});
</script>
</body>
</html>"""
