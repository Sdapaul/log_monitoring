#!/usr/bin/env python3
"""
개인정보 오남용·과다조회 점검 시스템 - 웹 인터페이스
Usage: python web_app.py [--port PORT] [--host HOST]
"""
from __future__ import annotations
import sys
import os
import uuid
import threading
import json
import glob
import argparse
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from flask import Flask, request, jsonify, render_template_string, send_file, Response
    FLASK_AVAILABLE = True
except ImportError:
    print("[오류] Flask가 설치되지 않았습니다. 아래 명령으로 설치하세요:")
    print("  pip install flask")
    sys.exit(1)

from utils.date_utils import parse_date_arg

# ── 앱 설정 ─────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

BASE_DIR    = Path(__file__).parent
UPLOAD_DIR  = BASE_DIR / 'uploads'
REPORTS_DIR = BASE_DIR / 'reports'
HISTORY_DIR = BASE_DIR / 'history'

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


# ── 작업 관리 ────────────────────────────────────────────────
def _make_job(job_id: str) -> dict:
    return {
        'id': job_id, 'status': 'pending',
        'progress': 0, 'message': '대기 중...',
        'result': None, 'error': None,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'log': [],
    }


def _update_job(job_id: str, **kw):
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(kw)
            if kw.get('message'):
                ts = datetime.now().strftime('%H:%M:%S')
                JOBS[job_id]['log'].append(f"[{ts}] {kw['message']}")


def _progress_cb(job_id: str):
    def _cb(pct: int, msg: str):
        _update_job(job_id, progress=pct, message=msg)
    return _cb


def _run_analysis_job(job_id: str, params: dict):
    """백그라운드 분석 실행"""
    _update_job(job_id, status='running', progress=2, message='분석 시작 중...')
    try:
        from pipeline.runner import run_analysis

        start_date = parse_date_arg(params['start_date'])
        end_date   = parse_date_arg(params['end_date'])
        job_dir    = REPORTS_DIR / job_id

        result = run_analysis(
            log_files      = params['log_files'],
            start_date     = start_date,
            end_date       = end_date,
            output_dir     = job_dir,
            check_misuse   = params.get('check_misuse', True),
            check_excess   = params.get('check_excess', True),
            min_risk_level = params.get('min_risk_level', 'LOW'),
            log_format     = params.get('log_format', 'auto'),
            report_formats = params.get('report_formats', ['html', 'excel']),
            progress       = _progress_cb(job_id),
            history_dir    = HISTORY_DIR,
        )

        summaries = result['summaries']
        just_items = result.get('justification_items', [])
        _update_job(
            job_id,
            status='done', progress=100, message='분석 완료!',
            result={
                'summaries':          [_summary_to_dict(s) for s in summaries],
                'justification':      [j.to_dict() for j in just_items],
                'report_files':       result['report_files'],
                'total_events':       result['total_events'],
                'total_lines':        result['total_lines'],
                'elapsed':            round(result['elapsed'], 1),
                'stats':              _compute_stats(summaries),
                'week_period':        result['week_period'],
                'month_period':       result['month_period'],
                'check_misuse':       result['check_misuse'],
                'check_excess':       result['check_excess'],
            }
        )
    except Exception as e:
        import traceback
        _update_job(job_id, status='error', message=str(e), error=traceback.format_exc())


def _summary_to_dict(s) -> dict:
    return {
        'user_id':                   s.user_id,
        'risk_score':                s.risk_score,
        'risk_level':                s.risk_level,
        'total_events':              s.total_events,
        'pii_event_count':           s.pii_event_count,
        'pii_types_str':             s.pii_types_str,
        'max_queries_per_hour':      s.max_queries_per_hour,
        'max_queries_per_day':       s.max_queries_per_day,
        'after_hours_count':         s.after_hours_count,
        'bulk_export_count':         s.bulk_export_count,
        'flagged_event_count':       s.flagged_event_count,
        'total_pii_records_exposed': s.total_pii_records_exposed,
        'max_single_query_exposure': s.max_single_query_exposure,
        'select_pii_query_count':    s.select_pii_query_count,
        'peak_hour':                 s.peak_hour,
        'peak_day':                  s.peak_day,
    }


def _compute_stats(summaries) -> dict:
    return {
        'total_users':     len(summaries),
        'critical_users':  sum(1 for s in summaries if s.risk_level == 'CRITICAL'),
        'high_users':      sum(1 for s in summaries if s.risk_level == 'HIGH'),
        'medium_users':    sum(1 for s in summaries if s.risk_level == 'MEDIUM'),
        'low_users':       sum(1 for s in summaries if s.risk_level == 'LOW'),
        'total_findings':  sum(s.flagged_event_count for s in summaries),
        'total_exposed':   sum(s.total_pii_records_exposed for s in summaries),
        'max_single':      max((s.max_single_query_exposure for s in summaries), default=0),
    }


# ── Routes ──────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/analyze', methods=['POST'])
def start_analysis():
    """분석 작업 시작 → job_id 반환"""
    log_files = []

    # 파일 업로드
    uploaded = request.files.getlist('log_files')
    if uploaded and any(f.filename for f in uploaded):
        tmp_dir = UPLOAD_DIR / str(uuid.uuid4())[:8]
        tmp_dir.mkdir(parents=True, exist_ok=True)
        for f in uploaded:
            if f.filename:
                dest = tmp_dir / Path(f.filename).name
                f.save(str(dest))
                log_files.append(str(dest))

    # 경로 직접 입력
    raw_paths = request.form.get('file_paths', '').strip()
    if raw_paths:
        for line in raw_paths.splitlines():
            pat = line.strip()
            if not pat:
                continue
            matches = glob.glob(pat)
            if matches:
                log_files.extend(matches)
            elif os.path.isfile(pat):
                log_files.append(pat)

    if not log_files:
        return jsonify({'error': '분석할 로그 파일이 없습니다. 파일을 업로드하거나 경로를 입력하세요.'}), 400

    start_date_str = request.form.get('start_date', '').strip()
    end_date_str   = request.form.get('end_date', '').strip()
    if not start_date_str or not end_date_str:
        return jsonify({'error': '시작 날짜와 종료 날짜를 입력하세요.'}), 400
    try:
        sd = parse_date_arg(start_date_str)
        ed = parse_date_arg(end_date_str)
        if sd > ed:
            return jsonify({'error': '시작 날짜가 종료 날짜보다 늦을 수 없습니다.'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    check_misuse = 'check_misuse' in request.form
    check_excess = 'check_excess' in request.form
    if not check_misuse and not check_excess:
        return jsonify({'error': '오남용 또는 과다조회 중 하나 이상을 선택하세요.'}), 400

    report_formats = request.form.getlist('report_formats') or ['html', 'excel']

    job_id = str(uuid.uuid4())[:8]
    params = {
        'log_files':      sorted(set(log_files)),
        'start_date':     start_date_str,
        'end_date':       end_date_str,
        'check_misuse':   check_misuse,
        'check_excess':   check_excess,
        'min_risk_level': request.form.get('min_risk_level', 'LOW'),
        'log_format':     request.form.get('log_format', 'auto'),
        'report_formats': report_formats,
    }

    with JOBS_LOCK:
        JOBS[job_id] = _make_job(job_id)
        JOBS[job_id]['params'] = params

    t = threading.Thread(target=_run_analysis_job, args=(job_id, params), daemon=True)
    t.start()
    return jsonify({'job_id': job_id})


@app.route('/api/status/<job_id>')
def job_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({'error': '작업을 찾을 수 없습니다.'}), 404
    return jsonify({
        'id':         job['id'],
        'status':     job['status'],
        'progress':   job['progress'],
        'message':    job['message'],
        'error':      job.get('error'),
        'log':        job.get('log', [])[-30:],
        'result':     job.get('result'),
        'created_at': job['created_at'],
    })


@app.route('/api/download/<job_id>/<fmt>')
def download_report(job_id: str, fmt: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job.get('status') != 'done':
        return jsonify({'error': '분석이 완료되지 않았습니다.'}), 404

    ext_map = {'excel': '.xlsx', 'html': '.html'}
    ext = ext_map.get(fmt)
    if not ext:
        return jsonify({'error': '지원하지 않는 형식입니다.'}), 400

    files = job.get('result', {}).get('report_files', [])
    matching = [f for f in files if f.endswith(ext)]
    if not matching or not os.path.isfile(matching[0]):
        return jsonify({'error': f'{fmt} 보고서가 없습니다.'}), 404

    return send_file(matching[0], as_attachment=True,
                     download_name=Path(matching[0]).name)


@app.route('/api/jobs')
def list_jobs():
    with JOBS_LOCK:
        items = list(JOBS.values())
    items.sort(key=lambda j: j['created_at'], reverse=True)
    return jsonify([{
        'id': j['id'], 'status': j['status'],
        'progress': j['progress'], 'message': j['message'],
        'created_at': j['created_at'],
        'params': j.get('params', {}),
    } for j in items[:50]])


# ── HTML 템플릿 ─────────────────────────────────────────────
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>개인정보 오남용·과다조회 점검 시스템</title>
<link rel="stylesheet" href="/static/css/bootstrap.min.css">
<link rel="stylesheet" href="/static/css/dataTables.bootstrap5.min.css">
<style>
  body { font-family: '맑은 고딕', 'Malgun Gothic', sans-serif; background: #f0f4f8; }
  .sys-header {
    background: linear-gradient(135deg, #1F4E79 0%, #2E75B6 100%);
    color: white; padding: 1.2rem 2rem; box-shadow: 0 2px 8px rgba(0,0,0,.25);
  }
  .sys-header h1 { font-size: 1.4rem; margin: 0; }
  .sys-header .sub { font-size: .85rem; opacity: .85; }
  .card { border: none; box-shadow: 0 2px 8px rgba(0,0,0,.08); border-radius: 10px; }
  .card-header-blue { background: #1F4E79; color: white; border-radius: 10px 10px 0 0 !important; }
  .section-label { font-weight: 700; color: #1F4E79; font-size: .95rem; }
  .drop-zone {
    border: 2px dashed #2E75B6; border-radius: 8px; padding: 2rem;
    text-align: center; cursor: pointer; transition: .2s;
    background: #f8fbff; color: #2E75B6;
  }
  .drop-zone.dragover { background: #e3f0ff; border-color: #1F4E79; }
  .check-toggle .btn-check:checked + .btn { font-weight: 700; }
  .progress-log {
    background: #1a1a2e; color: #e0e0e0; font-family: monospace;
    font-size: .82rem; border-radius: 6px; padding: 1rem;
    max-height: 200px; overflow-y: auto; margin-top: .5rem;
  }
  .stat-card { border-left: 5px solid; border-radius: 8px; }
  .stat-critical { border-left-color: #dc3545; }
  .stat-high     { border-left-color: #fd7e14; }
  .stat-medium   { border-left-color: #ffc107; }
  .stat-exposed  { border-left-color: #6f42c1; }
  .table th { background: #1F4E79; color: white; white-space: nowrap; }
  .badge-CRITICAL { background-color: #dc3545 !important; }
  .badge-HIGH     { background-color: #fd7e14 !important; }
  .badge-MEDIUM   { background-color: #17a2b8 !important; }
  .badge-LOW      { background-color: #28a745 !important; }
  .risk-CRITICAL  { background-color: #fff5f5; }
  .risk-HIGH      { background-color: #fff8f0; }
  .risk-MEDIUM    { background-color: #f0fbff; }
  #section-progress, #section-results { display: none; }
  .job-history-item { font-size: .85rem; }
  .tag-misuse { background: #e8f4ff; color: #0d6efd; border-radius: 4px; padding: 2px 6px; font-size:.8rem; }
  .tag-excess { background: #fff3e0; color: #fd7e14; border-radius: 4px; padding: 2px 6px; font-size:.8rem; }
</style>
</head>
<body>

<!-- 헤더 -->
<div class="sys-header d-flex align-items-center gap-3">
  <div>
    <h1>개인정보 오남용·과다조회 점검 시스템</h1>
    <div class="sub">Personal Information Misuse &amp; Excessive Access Detection</div>
  </div>
  <div class="ms-auto text-end small opacity-75">
    <div id="clock"></div>
  </div>
</div>

<div class="container-fluid py-4" style="max-width:1400px">
<div class="row g-4">

<!-- ══ 좌측: 입력 폼 ══ -->
<div class="col-lg-4">

  <!-- 점검 설정 카드 -->
  <div class="card mb-3" id="form-card">
    <div class="card-header card-header-blue py-2">
      <strong>점검 설정</strong>
    </div>
    <div class="card-body">

      <!-- 로그 파일 -->
      <div class="mb-3">
        <div class="section-label mb-2">1. 로그 파일</div>
        <div class="drop-zone" id="dropZone">
          <div class="fs-3 mb-1">&#128196;</div>
          <div>파일을 여기에 드래그하거나 클릭하여 선택</div>
          <div class="small text-muted mt-1">.log, .gz 등 다중 선택 가능</div>
          <input type="file" id="fileInput" multiple accept=".log,.gz,.txt,.audit,.json"
                 style="display:none">
        </div>
        <div id="fileList" class="mt-2 small text-muted"></div>

        <div class="mt-2">
          <label class="form-label small text-muted mb-1">또는 서버 경로 직접 입력 (한 줄에 하나, glob 패턴 가능)</label>
          <textarea class="form-control form-control-sm font-monospace" id="filePaths" rows="2"
            placeholder="예: C:\logs\mysql_audit.log&#10;C:\logs\*.log"></textarea>
        </div>
      </div>

      <hr class="my-3">

      <!-- 분석 기간 -->
      <div class="mb-3">
        <div class="section-label mb-2">2. 분석 기간</div>
        <div class="row g-2">
          <div class="col">
            <label class="form-label small">시작일</label>
            <input type="date" class="form-control form-control-sm" id="startDate">
          </div>
          <div class="col">
            <label class="form-label small">종료일</label>
            <input type="date" class="form-control form-control-sm" id="endDate">
          </div>
        </div>
        <div class="mt-2 d-flex gap-1 flex-wrap">
          <button class="btn btn-outline-secondary btn-sm" onclick="setDateRange(7)">최근 7일</button>
          <button class="btn btn-outline-secondary btn-sm" onclick="setDateRange(30)">최근 30일</button>
          <button class="btn btn-outline-secondary btn-sm" onclick="setDateRange(90)">최근 90일</button>
          <button class="btn btn-outline-secondary btn-sm" onclick="setThisMonth()">이번 달</button>
        </div>
      </div>

      <hr class="my-3">

      <!-- 점검 항목 선택 -->
      <div class="mb-3">
        <div class="section-label mb-2">3. 점검 항목 선택</div>
        <div class="d-flex gap-2 check-toggle">
          <input type="checkbox" class="btn-check" id="chkMisuse" autocomplete="off" checked>
          <label class="btn btn-outline-primary w-50 py-2" for="chkMisuse">
            <div class="fs-5">&#128274;</div>
            <div class="fw-bold">개인정보 오남용</div>
            <div class="small opacity-75">PII 노출·야간 조회</div>
          </label>

          <input type="checkbox" class="btn-check" id="chkExcess" autocomplete="off" checked>
          <label class="btn btn-outline-warning w-50 py-2" for="chkExcess">
            <div class="fs-5">&#128200;</div>
            <div class="fw-bold">과다조회</div>
            <div class="small opacity-75">반복·대량 접근</div>
          </label>
        </div>
        <div id="selectionWarning" class="text-danger small mt-1" style="display:none">
          하나 이상 선택해야 합니다.
        </div>

        <!-- 항목 설명 -->
        <div class="mt-2 small text-muted p-2 rounded" style="background:#f8f9fa">
          <div id="desc-misuse"><strong>&#128274; 오남용:</strong> SELECT절 PII 노출, 야간 개인정보 조회, 대량 레코드 반환</div>
          <div id="desc-excess" class="mt-1"><strong>&#128200; 과다조회:</strong> 시간당/일당 임계값 초과, 대량 조회(BULK), 대상 다양성</div>
        </div>
      </div>

      <hr class="my-3">

      <!-- 고급 설정 -->
      <div class="mb-3">
        <div class="section-label mb-1">
          <a class="text-decoration-none text-reset" data-bs-toggle="collapse" href="#advancedSettings">
            4. 고급 설정 &#9660;
          </a>
        </div>
        <div class="collapse" id="advancedSettings">
          <div class="row g-2 mt-1">
            <div class="col-6">
              <label class="form-label small">최소 위험 등급</label>
              <select class="form-select form-select-sm" id="minRisk">
                <option value="LOW" selected>LOW 이상 (전체)</option>
                <option value="MEDIUM">MEDIUM 이상</option>
                <option value="HIGH">HIGH 이상</option>
                <option value="CRITICAL">CRITICAL만</option>
              </select>
            </div>
            <div class="col-6">
              <label class="form-label small">로그 형식</label>
              <select class="form-select form-select-sm" id="logFormat">
                <option value="auto" selected>자동 감지</option>
                <option value="db">DB 감사 로그</option>
                <option value="web">웹 접근 로그</option>
                <option value="app">앱 로그 (Log4j)</option>
                <option value="generic">범용</option>
              </select>
            </div>
          </div>
          <div class="mt-2">
            <label class="form-label small">보고서 형식</label>
            <div class="d-flex gap-3">
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="fmtHtml" value="html" checked>
                <label class="form-check-label small" for="fmtHtml">HTML</label>
              </div>
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="fmtExcel" value="excel" checked>
                <label class="form-check-label small" for="fmtExcel">Excel</label>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 시작 버튼 -->
      <button class="btn btn-primary w-100 py-2 fw-bold" id="btnStart" onclick="startAnalysis()">
        &#128269; 점검 시작
      </button>
    </div>
  </div>

  <!-- 최근 작업 이력 -->
  <div class="card" id="card-history">
    <div class="card-header card-header-blue py-2 d-flex align-items-center">
      <strong>최근 점검 이력</strong>
      <button class="btn btn-sm btn-outline-light ms-auto" onclick="loadJobHistory()">&#8635;</button>
    </div>
    <div class="card-body p-2" id="jobHistory">
      <div class="text-muted small text-center py-2">이력 없음</div>
    </div>
  </div>
</div>

<!-- ══ 우측: 진행 + 결과 ══ -->
<div class="col-lg-8">

  <!-- 진행 섹션 -->
  <div id="section-progress">
    <div class="card mb-3">
      <div class="card-header card-header-blue py-2 d-flex align-items-center">
        <strong>점검 진행 중</strong>
        <span class="ms-2 badge bg-warning text-dark" id="prog-status">실행 중</span>
      </div>
      <div class="card-body">
        <div class="d-flex justify-content-between small mb-1">
          <span id="prog-msg">준비 중...</span>
          <span id="prog-pct">0%</span>
        </div>
        <div class="progress mb-3" style="height:22px">
          <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary"
               id="progressBar" style="width:0%"></div>
        </div>
        <div class="progress-log" id="progressLog"></div>
      </div>
    </div>
  </div>

  <!-- 결과 섹션 -->
  <div id="section-results">
    <!-- 요약 카드 -->
    <div class="row g-3 mb-3" id="stat-cards"></div>

    <!-- 점검 항목 배지 -->
    <div class="mb-2" id="check-badges"></div>

    <!-- ★ 소명 요청 우선순위 ★ -->
    <div class="card mb-3 border-danger border-2" id="justification-card" style="display:none">
      <div class="card-header py-2 d-flex align-items-center"
           style="background:#8B0000;color:white">
        <strong>소명 요청 우선순위</strong>
        <span class="ms-2 badge bg-warning text-dark">조사 필요</span>
        <span class="ms-auto small opacity-75">위반 중요도 기준 자동 정렬</span>
      </div>
      <div class="card-body p-2" id="justification-list"></div>
    </div>

    <!-- 사용자 위험 테이블 -->
    <div class="card mb-3">
      <div class="card-header card-header-blue py-2 d-flex align-items-center">
        <strong>사용자별 위험 현황 (전체)</strong>
        <span class="ms-auto small opacity-75" id="result-period"></span>
      </div>
      <div class="card-body table-responsive p-0">
        <table id="userTable" class="table table-sm table-hover table-bordered mb-0">
          <thead>
            <tr>
              <th>사원ID</th><th>위험등급</th><th>위험점수</th>
              <th>PII접촉</th><th>PII노출레코드</th><th>단일최대노출</th>
              <th>최대/시간</th><th>최대/일</th><th>야간조회</th>
              <th>대량조회</th><th>이상건수</th><th>소명</th>
            </tr>
          </thead>
          <tbody id="userTableBody"></tbody>
        </table>
      </div>
    </div>

    <!-- 다운로드 -->
    <div class="card mb-3">
      <div class="card-header card-header-blue py-2"><strong>보고서 다운로드</strong></div>
      <div class="card-body d-flex gap-3 flex-wrap" id="download-buttons"></div>
    </div>

    <!-- 차트 -->
    <div class="row g-3 mb-3">
      <div class="col-md-5">
        <div class="card h-100">
          <div class="card-header py-2 fw-bold small">위험 등급 분포</div>
          <div class="card-body" style="height:240px"><canvas id="riskChart"></canvas></div>
        </div>
      </div>
      <div class="col-md-7">
        <div class="card h-100">
          <div class="card-header py-2 fw-bold small">소명 우선순위 (위반 중요도 점수)</div>
          <div class="card-body" style="height:240px"><canvas id="topChart"></canvas></div>
        </div>
      </div>
    </div>

    <div class="text-end mb-4">
      <button class="btn btn-outline-secondary" onclick="resetForm()">&#8592; 다시 점검하기</button>
    </div>
  </div>

  <!-- ══ 소명 상세 모달 ══ -->
  <div class="modal fade" id="justModal" tabindex="-1">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header" style="background:#1F4E79;color:white">
          <h5 class="modal-title" id="justModalTitle">소명 요청 상세</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body" id="justModalBody"></div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
        </div>
      </div>
    </div>
  </div>

</div><!-- col -->
</div><!-- row -->
</div><!-- container -->

<script src="/static/js/jquery.min.js"></script>
<script src="/static/js/bootstrap.bundle.min.js"></script>
<script src="/static/js/jquery.dataTables.min.js"></script>
<script src="/static/js/dataTables.bootstrap5.min.js"></script>
<script src="/static/js/chart.umd.min.js"></script>
<script>
// ── 시계 ────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent = now.toLocaleString('ko-KR');
}
setInterval(updateClock, 1000); updateClock();

// ── 날짜 헬퍼 ───────────────────────────────────────────
function fmtDate(d) {
  return d.toISOString().split('T')[0];
}
function setDateRange(days) {
  const end = new Date(); end.setHours(23,59,59);
  const start = new Date(); start.setDate(start.getDate() - days + 1);
  document.getElementById('startDate').value = fmtDate(start);
  document.getElementById('endDate').value = fmtDate(end);
}
function setThisMonth() {
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), 1);
  const end = new Date(now.getFullYear(), now.getMonth() + 1, 0);
  document.getElementById('startDate').value = fmtDate(start);
  document.getElementById('endDate').value = fmtDate(end);
}
// 기본: 최근 30일
setDateRange(30);

// ── 파일 드래그 앤 드롭 ─────────────────────────────────
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
let selectedFiles = [];

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  selectedFiles = Array.from(e.dataTransfer.files);
  updateFileList();
});
fileInput.addEventListener('change', () => {
  selectedFiles = Array.from(fileInput.files);
  updateFileList();
});

function updateFileList() {
  const el = document.getElementById('fileList');
  if (!selectedFiles.length) { el.innerHTML = ''; return; }
  const items = selectedFiles.map(f =>
    `<span class="badge bg-secondary me-1">${f.name} (${(f.size/1024).toFixed(1)}KB)</span>`
  ).join('');
  el.innerHTML = `<div class="mt-1">${items}</div>`;
}

// ── 체크 토글 검증 ───────────────────────────────────────
document.getElementById('chkMisuse').addEventListener('change', validateChecks);
document.getElementById('chkExcess').addEventListener('change', validateChecks);
function validateChecks() {
  const ok = document.getElementById('chkMisuse').checked ||
             document.getElementById('chkExcess').checked;
  document.getElementById('selectionWarning').style.display = ok ? 'none' : 'block';
  return ok;
}

// ── 점검 시작 ───────────────────────────────────────────
let currentJobId = null;
let pollTimer = null;
let dtInstance = null;
let riskChart = null, topChart = null;

function startAnalysis() {
  if (!validateChecks()) return;

  const startDate = document.getElementById('startDate').value;
  const endDate   = document.getElementById('endDate').value;
  if (!startDate || !endDate) { alert('분석 기간을 입력하세요.'); return; }

  const paths = document.getElementById('filePaths').value.trim();
  if (!selectedFiles.length && !paths) {
    alert('로그 파일을 업로드하거나 경로를 입력하세요.'); return;
  }

  const fd = new FormData();
  selectedFiles.forEach(f => fd.append('log_files', f));
  fd.append('file_paths', paths);
  fd.append('start_date', startDate);
  fd.append('end_date', endDate);
  if (document.getElementById('chkMisuse').checked) fd.append('check_misuse', '1');
  if (document.getElementById('chkExcess').checked) fd.append('check_excess', '1');
  fd.append('min_risk_level', document.getElementById('minRisk').value);
  fd.append('log_format', document.getElementById('logFormat').value);
  if (document.getElementById('fmtHtml').checked)  fd.append('report_formats', 'html');
  if (document.getElementById('fmtExcel').checked) fd.append('report_formats', 'excel');

  document.getElementById('btnStart').disabled = true;
  document.getElementById('section-progress').style.display = 'block';
  document.getElementById('section-results').style.display = 'none';
  document.getElementById('progressLog').textContent = '';
  document.getElementById('progressBar').style.width = '0%';
  document.getElementById('prog-msg').textContent = '요청 전송 중...';
  document.getElementById('prog-pct').textContent = '0%';

  fetch('/api/analyze', { method: 'POST', body: fd })
    .then(r => r.json())
    .then(data => {
      if (data.error) { showError(data.error); return; }
      currentJobId = data.job_id;
      pollProgress();
    })
    .catch(e => showError('서버 연결 오류: ' + e));
}

function pollProgress() {
  if (!currentJobId) return;
  fetch('/api/status/' + currentJobId)
    .then(r => r.json())
    .then(data => {
      updateProgress(data);
      if (data.status === 'done') {
        showResults(data.result);
        loadJobHistory();
      } else if (data.status === 'error') {
        showError(data.message + '\n' + (data.error || ''));
      } else {
        pollTimer = setTimeout(pollProgress, 1000);
      }
    })
    .catch(() => { pollTimer = setTimeout(pollProgress, 2000); });
}

function updateProgress(data) {
  const pct = data.progress || 0;
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('prog-pct').textContent = pct + '%';
  document.getElementById('prog-msg').textContent = data.message || '';
  const logEl = document.getElementById('progressLog');
  if (data.log && data.log.length) {
    logEl.textContent = data.log.join('\n');
    logEl.scrollTop = logEl.scrollHeight;
  }
  const statusEl = document.getElementById('prog-status');
  const statusMap = { pending:'대기', running:'실행 중', done:'완료', error:'오류' };
  statusEl.textContent = statusMap[data.status] || data.status;
  const clsMap = { pending:'bg-secondary', running:'bg-warning text-dark', done:'bg-success', error:'bg-danger' };
  statusEl.className = 'ms-2 badge ' + (clsMap[data.status] || 'bg-secondary');
}

// ── 결과 표시 ───────────────────────────────────────────
const RISK_BADGE = {
  CRITICAL: '<span class="badge badge-CRITICAL">위험</span>',
  HIGH:     '<span class="badge badge-HIGH">고위험</span>',
  MEDIUM:   '<span class="badge badge-MEDIUM">중위험</span>',
  LOW:      '<span class="badge badge-LOW">저위험</span>',
};
const RISK_ROW = { CRITICAL:'risk-CRITICAL', HIGH:'risk-HIGH', MEDIUM:'risk-MEDIUM', LOW:'' };
const URGENCY_STYLE = {
  '즉시': 'background:#8B0000;color:white',
  '긴급': 'background:#fd7e14;color:white',
  '검토': 'background:#1F4E79;color:white',
};

let justificationData = [];

function showResults(result) {
  document.getElementById('section-results').style.display = 'block';
  const stats = result.stats;
  justificationData = result.justification || [];

  // 요약 카드
  const jCount = justificationData.length;
  document.getElementById('stat-cards').innerHTML = `
    <div class="col-6 col-lg-3">
      <div class="card stat-card stat-critical p-3 text-center">
        <div class="fs-1 fw-bold text-danger">${stats.critical_users}</div>
        <div class="small text-muted">위험(CRITICAL)</div>
      </div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card stat-card stat-high p-3 text-center">
        <div class="fs-1 fw-bold text-warning">${stats.high_users}</div>
        <div class="small text-muted">고위험(HIGH)</div>
      </div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card stat-card stat-medium p-3 text-center">
        <div class="fs-2 fw-bold text-info">${stats.total_exposed.toLocaleString()}</div>
        <div class="small text-muted">PII 노출 레코드</div>
      </div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card p-3 text-center" style="border-left:5px solid #8B0000">
        <div class="fs-1 fw-bold" style="color:#8B0000">${jCount}</div>
        <div class="small text-muted">소명 요청 대상자</div>
      </div>
    </div>`;

  // 배지
  let badges = '';
  if (result.check_misuse) badges += '<span class="tag-misuse me-1">&#128274; 오남용 점검</span>';
  if (result.check_excess) badges += '<span class="tag-excess me-2">&#128200; 과다조회 점검</span>';
  badges += `<span class="text-muted small">총 ${result.total_lines.toLocaleString()}줄 분석 · ${result.elapsed}초</span>`;
  document.getElementById('check-badges').innerHTML = badges;
  document.getElementById('result-period').textContent =
    `${document.getElementById('startDate').value} ~ ${document.getElementById('endDate').value}`;

  // 소명 우선순위 렌더링
  renderJustificationList(justificationData);

  // 사용자 테이블
  if (dtInstance) { dtInstance.destroy(); dtInstance = null; }
  // 소명 index 맵 (user_id → rank)
  const justMap = {};
  justificationData.forEach(j => { justMap[j.user_id] = j; });

  document.getElementById('userTableBody').innerHTML = result.summaries.map(s => {
    const jitem = justMap[s.user_id];
    const jCell = jitem
      ? `<button class="btn btn-sm btn-outline-danger py-0 px-1"
           onclick="openJustModal('${s.user_id}')">
           #${jitem.priority_rank} 소명요청</button>`
      : '<span class="text-muted small">-</span>';
    return `<tr class="${RISK_ROW[s.risk_level]||''}">
      <td><strong>${s.user_id}</strong></td>
      <td>${RISK_BADGE[s.risk_level]||s.risk_level}</td>
      <td class="text-end fw-bold">${s.risk_score.toFixed(1)}</td>
      <td class="text-end">${s.pii_event_count.toLocaleString()}</td>
      <td class="text-end ${s.total_pii_records_exposed>10000?'text-danger fw-bold':''}">${s.total_pii_records_exposed.toLocaleString()}</td>
      <td class="text-end ${s.max_single_query_exposure>=5000?'text-warning fw-bold':''}">${s.max_single_query_exposure.toLocaleString()}</td>
      <td class="text-end">${s.max_queries_per_hour.toLocaleString()}</td>
      <td class="text-end">${s.max_queries_per_day.toLocaleString()}</td>
      <td class="text-end">${s.after_hours_count.toLocaleString()}</td>
      <td class="text-end">${s.bulk_export_count.toLocaleString()}</td>
      <td class="text-end">${s.flagged_event_count.toLocaleString()}</td>
      <td>${jCell}</td>
    </tr>`;
  }).join('');

  dtInstance = $('#userTable').DataTable({
    order:[[2,'desc']], pageLength:20,
    language:{ search:'검색:', lengthMenu:'_MENU_ 행',
      info:'_START_-_END_ / _TOTAL_ 명',
      paginate:{first:'처음',last:'끝',next:'다음',previous:'이전'} }
  });

  // 다운로드
  const jobId = currentJobId;
  let dlHtml = '';
  if (result.report_files && result.report_files.length) {
    if (result.report_files.some(f=>f.endsWith('.xlsx')))
      dlHtml += `<a href="/api/download/${jobId}/excel" class="btn btn-success">
        &#128202; Excel 보고서 (소명 양식 포함)</a>`;
    if (result.report_files.some(f=>f.endsWith('.html')))
      dlHtml += `<a href="/api/download/${jobId}/html" class="btn btn-info text-white">
        &#127758; HTML 보고서</a>`;
  } else {
    dlHtml = '<div class="text-muted small">보고서 없음</div>';
  }
  document.getElementById('download-buttons').innerHTML = dlHtml;

  drawCharts(result.summaries, justificationData);
}

// ── 소명 우선순위 카드 렌더링 ────────────────────────────
function renderJustificationList(items) {
  const card = document.getElementById('justification-card');
  const list = document.getElementById('justification-list');
  if (!items || !items.length) { card.style.display='none'; return; }
  card.style.display = 'block';

  list.innerHTML = items.map(item => {
    const urgStyle = URGENCY_STYLE[item.urgency] || 'background:#1F4E79;color:white';
    const reasons2 = item.reasons.slice(0,2).map(r=>
      `<div class="small text-muted mt-1">• ${escHtml(r)}</div>`).join('');
    return `
    <div class="border rounded mb-2 overflow-hidden">
      <div class="d-flex align-items-center p-2 gap-2"
           style="${item.risk_level==='CRITICAL'?'background:#fff5f5':'background:#fff8f0'}">
        <!-- 순위 -->
        <div class="text-center fw-bold rounded px-2 py-1 me-1 flex-shrink-0"
             style="${urgStyle};min-width:52px">
          <div style="font-size:1.2rem">#${item.priority_rank}</div>
          <div style="font-size:.7rem">${item.urgency}</div>
        </div>
        <!-- 사용자 정보 -->
        <div class="flex-grow-1">
          <div class="d-flex align-items-center gap-2 mb-1">
            <strong class="fs-5">${item.user_id}</strong>
            ${RISK_BADGE[item.risk_level]||''}
            <span class="text-muted small">위험점수 ${item.risk_score.toFixed(1)}</span>
          </div>
          <div class="small fw-bold text-dark">${escHtml(item.summary_one_line)}</div>
          ${reasons2}
        </div>
        <!-- 버튼 -->
        <div class="d-flex flex-column gap-1 flex-shrink-0">
          <button class="btn btn-sm btn-outline-dark"
                  onclick="openJustModal('${item.user_id}')">&#128196; 소명 근거 상세</button>
        </div>
      </div>
    </div>`;
  }).join('');
}

// ── 소명 상세 모달 ────────────────────────────────────────
function openJustModal(userId) {
  const item = justificationData.find(j => j.user_id === userId);
  if (!item) return;

  document.getElementById('justModalTitle').textContent =
    `소명 요청 상세 — ${userId} (우선순위 #${item.priority_rank} · ${item.urgency})`;

  const reasonsHtml = item.reasons.map((r,i)=>
    `<div class="mb-1"><span class="badge bg-secondary me-1">${i+1}</span>${escHtml(r)}</div>`
  ).join('');

  const questionsHtml = item.questions.map((q,i)=>
    `<div class="mb-2 p-2 rounded" style="background:#f8f9fa;border-left:3px solid #1F4E79">
       <span class="fw-bold text-primary me-1">Q${i+1}.</span>${escHtml(q)}
     </div>`
  ).join('');

  const findingsHtml = item.key_findings.length ? item.key_findings.map(f=>`
    <div class="border rounded p-2 mb-2 ${f.severity==='CRITICAL'?'border-danger':''}">
      <div class="d-flex align-items-center gap-2 mb-1">
        <span class="badge badge-${f.severity}">${f.severity_kr}</span>
        <span class="fw-bold small">${f.category_kr}</span>
        <span class="text-muted small ms-auto">${f.timestamp_str}</span>
      </div>
      <div class="small fw-bold mb-1">${escHtml(f.summary)}</div>
      ${f.exposure_type_kr ? `<div class="small text-muted">노출 유형: ${f.exposure_type_kr}</div>` : ''}
      ${f.result_rows!=null ? `<div class="small text-muted">반환 건수: ${f.result_rows.toLocaleString()}건</div>` : ''}
      <div class="font-monospace small text-break mt-1 p-1 rounded"
           style="background:#f8f9fa;font-size:.78rem">${escHtml(f.evidence)}</div>
      <div class="text-muted" style="font-size:.72rem">참조: ${f.raw_reference}</div>
    </div>`).join('')
    : '<div class="text-muted small">핵심 증거 없음</div>';

  document.getElementById('justModalBody').innerHTML = `
    <!-- 소명 요청 배너 -->
    <div class="alert py-2 mb-3" style="background:#8B0000;color:white">
      <strong>소명 요청 대상자:</strong> ${item.user_id} &nbsp;|&nbsp;
      위험등급: ${item.risk_level} (${item.risk_score.toFixed(1)}점) &nbsp;|&nbsp;
      우선순위: ${item.urgency} (#${item.priority_rank}위)
    </div>

    <!-- 위반 이유 -->
    <h6 class="fw-bold border-bottom pb-1 mb-2" style="color:#8B0000">
      &#9888; 위반 이유 (소명 근거)
    </h6>
    <div class="mb-3">${reasonsHtml}</div>

    <!-- 화면 노출 추정 -->
    <h6 class="fw-bold border-bottom pb-1 mb-2" style="color:#1F4E79">
      &#128247; 화면에 표시된 것으로 추정되는 개인정보
    </h6>
    <div class="mb-3 p-3 rounded" style="background:#f0f4ff;white-space:pre-wrap;font-size:.88rem">${escHtml(item.screen_estimate)}</div>

    <!-- 핵심 증거 -->
    <h6 class="fw-bold border-bottom pb-1 mb-2" style="color:#1F4E79">
      &#128269; 핵심 증거 (로그 기반, 개인정보 마스킹 처리)
    </h6>
    <div class="mb-3">${findingsHtml}</div>

    <!-- 소명 질문 -->
    <h6 class="fw-bold border-bottom pb-1 mb-2" style="color:#1F4E79">
      &#10067; 소명 요청 질문 (사용자에게 답변 요청)
    </h6>
    <div class="mb-3">${questionsHtml}</div>

    <!-- 실제 화면 확인 방법 안내 -->
    <div class="alert alert-info py-2 small mb-0">
      <strong>&#128161; 실제 화면 조회 내용 정확히 확인하려면:</strong><br>
      ① DB 감사 로그에서 세션 ID별 Rows_sent 및 쿼리 결과 확인<br>
      ② 애플리케이션 서버 로그에서 API 응답 JSON 또는 화면 렌더링 데이터 확인<br>
      ③ DB Performance Schema &gt; events_statements_history 에서 쿼리별 결과 건수 조회<br>
      ④ DLP(데이터 유출 방지) 솔루션 또는 네트워크 패킷 캡처 분석<br>
      <span class="text-muted">※ 본 보고서의 노출량 수치는 SELECT 쿼리 분석 기반 <strong>추정값</strong>입니다.</span>
    </div>`;

  new bootstrap.Modal(document.getElementById('justModal')).show();
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function drawCharts(summaries, justItems) {
  if (riskChart) { riskChart.destroy(); riskChart = null; }
  if (topChart)  { topChart.destroy();  topChart  = null; }

  // 위험 등급 도넛
  const lv = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  summaries.forEach(s => { if(lv[s.risk_level]!==undefined) lv[s.risk_level]++; });
  riskChart = new Chart(document.getElementById('riskChart'), {
    type: 'doughnut',
    data: {
      labels: ['위험(CRITICAL)','고위험(HIGH)','중위험(MEDIUM)','저위험(LOW)'],
      datasets:[{data:[lv.CRITICAL,lv.HIGH,lv.MEDIUM,lv.LOW],
        backgroundColor:['#8B0000','#fd7e14','#17a2b8','#28a745']}]
    },
    options:{ responsive:true, maintainAspectRatio:false,
      plugins:{legend:{position:'bottom',labels:{font:{size:11}}}} }
  });

  // 소명 우선순위 막대 (priority_score 기준)
  const top10 = (justItems||[]).slice(0,10);
  const barColors = top10.map(j=>({
    '즉시':'#8B0000','긴급':'#fd7e14','검토':'#1F4E79'}[j.urgency]||'#888'));
  topChart = new Chart(document.getElementById('topChart'), {
    type:'bar',
    data:{
      labels: top10.map(j=>`#${j.priority_rank} ${j.user_id}`),
      datasets:[{label:'소명 우선순위 점수', data:top10.map(j=>j.priority_score),
        backgroundColor:barColors}]
    },
    options:{
      responsive:true, maintainAspectRatio:false, indexAxis:'y',
      plugins:{legend:{display:false},
        tooltip:{callbacks:{label:ctx=>`${ctx.raw.toFixed(0)}점 (${top10[ctx.dataIndex].urgency})`}}},
      scales:{x:{min:0}}
    }
  });
}

function showError(msg) {
  document.getElementById('prog-status').textContent = '오류';
  document.getElementById('prog-status').className = 'ms-2 badge bg-danger';
  document.getElementById('prog-msg').textContent = '오류 발생: ' + msg.split('\n')[0];
  document.getElementById('progressBar').classList.remove('progress-bar-animated');
  document.getElementById('progressBar').classList.add('bg-danger');
  document.getElementById('btnStart').disabled = false;
}

function resetForm() {
  document.getElementById('section-progress').style.display = 'none';
  document.getElementById('section-results').style.display = 'none';
  document.getElementById('btnStart').disabled = false;
  document.getElementById('progressBar').style.width = '0%';
  document.getElementById('progressBar').classList.add('progress-bar-animated');
  document.getElementById('progressBar').classList.remove('bg-danger');
  if (dtInstance) { dtInstance.destroy(); dtInstance = null; }
  currentJobId = null;
  if (pollTimer) clearTimeout(pollTimer);
}

// ── 작업 이력 ───────────────────────────────────────────
function loadJobHistory() {
  fetch('/api/jobs').then(r => r.json()).then(jobs => {
    const el = document.getElementById('jobHistory');
    if (!jobs.length) { el.innerHTML = '<div class="text-muted small text-center py-2">이력 없음</div>'; return; }
    const statusIcon = { pending:'&#9711;', running:'&#9654;', done:'&#10003;', error:'&#10007;' };
    const statusColor = { pending:'secondary', running:'warning', done:'success', error:'danger' };
    el.innerHTML = jobs.slice(0, 8).map(j => {
      const p = j.params || {};
      const tags = [];
      if (p.check_misuse) tags.push('<span class="tag-misuse">오남용</span>');
      if (p.check_excess) tags.push('<span class="tag-excess">과다조회</span>');
      return `<div class="job-history-item border-bottom py-2 px-1">
        <div class="d-flex align-items-center gap-2">
          <span class="badge bg-${statusColor[j.status]}">${statusIcon[j.status]}${j.status}</span>
          <span class="font-monospace text-muted">#${j.id}</span>
          <span class="ms-auto text-muted" style="font-size:.75rem">${j.created_at}</span>
        </div>
        <div class="mt-1">${tags.join(' ')}</div>
        <div class="text-muted" style="font-size:.78rem">${(p.start_date||'')} ~ ${(p.end_date||'')} | ${j.message}</div>
      </div>`;
    }).join('');
  });
}
loadJobHistory();
</script>
</body>
</html>"""


# ── 진입점 ──────────────────────────────────────────────────
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='개인정보 점검 시스템 웹 서버')
    ap.add_argument('--host', default='0.0.0.0', help='바인딩 주소 (기본: 0.0.0.0)')
    ap.add_argument('--port', type=int, default=5000, help='포트 번호 (기본: 5000)')
    ap.add_argument('--debug', action='store_true', help='Flask 디버그 모드')
    args = ap.parse_args()

    UPLOAD_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    HISTORY_DIR.mkdir(exist_ok=True)

    print("=" * 55)
    print("  개인정보 오남용·과다조회 점검 시스템 - 웹 서버")
    print("=" * 55)
    print(f"  URL  : http://localhost:{args.port}")
    print(f"  종료 : Ctrl+C")
    print("=" * 55)

    app.run(host=args.host, port=args.port, debug=args.debug,
            use_reloader=False, threaded=True)
