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
import zipfile
import tarfile
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


_LOG_EXTENSIONS = {'.log', '.txt', '.gz', '.audit', '.json', '.csv',
                   '.docx', '.pdf', '.xlsx', '.xls', '.xlsm', '.xml'}


def _extract_archive(path: Path, dest_dir: Path) -> list[str]:
    """
    zip / tar.gz / tar.bz2 아카이브를 dest_dir 하위에 풀고
    로그 파일 경로 목록을 반환합니다.
    압축 파일이 아니면 빈 목록 반환.
    경로 순회(path traversal) 방지: dest_dir 밖으로 추출하지 않습니다.
    """
    suffix = path.suffix.lower()
    suffixes = [s.lower() for s in path.suffixes]

    extracted: list[str] = []

    try:
        if suffix == '.zip':
            with zipfile.ZipFile(path, 'r') as zf:
                for member in zf.infolist():
                    member_path = (dest_dir / member.filename).resolve()
                    if not str(member_path).startswith(str(dest_dir.resolve())):
                        continue  # path traversal 차단
                    if member.is_dir():
                        continue
                    ext = Path(member.filename).suffix.lower()
                    if ext in _LOG_EXTENSIONS or ext == '':
                        zf.extract(member, dest_dir)
                        extracted.append(str(dest_dir / member.filename))

        elif '.tar' in suffixes or suffix in ('.tgz', '.tbz2'):
            mode = 'r:*'
            with tarfile.open(path, mode) as tf:
                for member in tf.getmembers():
                    member_path = (dest_dir / member.name).resolve()
                    if not str(member_path).startswith(str(dest_dir.resolve())):
                        continue
                    if not member.isfile():
                        continue
                    ext = Path(member.name).suffix.lower()
                    if ext in _LOG_EXTENSIONS or ext == '':
                        tf.extract(member, dest_dir, set_attrs=False)
                        extracted.append(str(dest_dir / member.name))

    except Exception as e:
        print(f"  [압축해제 오류] {path.name}: {e}")

    return extracted


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
                extracted = _extract_archive(dest, tmp_dir)
                if extracted:
                    dest.unlink(missing_ok=True)
                    log_files.extend(extracted)
                else:
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
  /* ── 도움말 ─────────────────────────────────────── */
  .guide-step { border-left: 4px solid #2E75B6; padding: .6rem 1rem; margin-bottom: .9rem; background: #f8fbff; border-radius: 0 6px 6px 0; }
  .guide-step .step-num { background:#1F4E79; color:white; border-radius:50%; width:26px; height:26px; display:inline-flex; align-items:center; justify-content:center; font-weight:700; font-size:.85rem; margin-right:.5rem; flex-shrink:0; }
  .log-example { background:#1a1a2e; color:#a8ff78; font-family:monospace; font-size:.76rem; border-radius:6px; padding:.7rem 1rem; margin:.4rem 0 .8rem; overflow-x:auto; white-space:pre; }
  .pii-row-CRITICAL td:first-child { border-left:4px solid #dc3545; }
  .pii-row-HIGH     td:first-child { border-left:4px solid #fd7e14; }
  .pii-row-MEDIUM   td:first-child { border-left:4px solid #17a2b8; }
  .help-modal .nav-tabs .nav-link { color:#1F4E79; font-weight:600; }
  .help-modal .nav-tabs .nav-link.active { background:#1F4E79; color:white; border-color:#1F4E79; }
  .welcome-card { background: linear-gradient(135deg,#f8fbff 0%,#e8f4ff 100%); border:1.5px solid #b8d4f0; border-radius:10px; padding:1.5rem; }
  .welcome-feature { display:flex; align-items:flex-start; gap:.75rem; margin-bottom:.85rem; }
  .welcome-icon { font-size:1.5rem; flex-shrink:0; }
  .threshold-table td, .threshold-table th { padding:.3rem .6rem; font-size:.83rem; }
  /* ── 탐지 흐름 다이어그램 ──────────────────────────── */
  .flow-wrap { display:flex; flex-direction:column; align-items:stretch; gap:0; }
  .flow-step { border-radius:8px; padding:.65rem 1rem; position:relative; }
  .flow-arrow { text-align:center; color:#adb5bd; font-size:1.1rem; line-height:1.4; }
  .flow-arrow-branch { display:flex; align-items:center; gap:.5rem; color:#adb5bd; font-size:.78rem; margin:.1rem 0; padding:0 .5rem; }
  .flow-arrow-branch .branch-line { flex:1; height:1px; background:#dee2e6; }
  .step-badge { display:inline-block; background:#1F4E79; color:white; border-radius:50%; width:22px; height:22px; text-align:center; line-height:22px; font-size:.75rem; font-weight:700; margin-right:.4rem; flex-shrink:0; }
  .flow-step-main  { background:#e8f4ff; border:1.5px solid #90c0f0; }
  .flow-step-ok    { background:#e8f8e8; border:1.5px solid #7ecb7e; }
  .flow-step-warn  { background:#fff8e1; border:1.5px solid #ffd54f; }
  .flow-step-skip  { background:#f8f9fa; border:1.5px dashed #ced4da; color:#6c757d; }
  .flow-step-final { background:#fff0f3; border:2px solid #f06090; }
  .flow-inline-code { background:rgba(0,0,0,.06); border-radius:3px; padding:.05rem .35rem; font-family:monospace; font-size:.8em; }
  .hangul-rule-box { background:#1a1a2e; color:#e0e0e0; border-radius:8px; padding:1rem 1.2rem; font-family:monospace; font-size:.78rem; line-height:1.8; }
  .hangul-rule-box .hr-in  { color:#aaa; }
  .hangul-rule-box .hr-arr { color:#ffd54f; }
  .hangul-rule-box .hr-out { color:#a8ff78; }
  .hangul-rule-box .hr-tag { color:#80d8ff; }
  .hangul-rule-box .hr-note{ color:#888; font-style:italic; }
</style>
</head>
<body>

<!-- 헤더 -->
<div class="sys-header d-flex align-items-center gap-3">
  <div>
    <h1>개인정보 오남용·과다조회 점검 시스템</h1>
    <div class="sub">Personal Information Misuse &amp; Excessive Access Detection</div>
  </div>
  <div class="ms-auto d-flex align-items-center gap-3">
    <button class="btn btn-outline-light btn-sm px-3"
            data-bs-toggle="modal" data-bs-target="#helpModal">
      &#9432; 사용 안내 &amp; 탐지 항목
    </button>
    <div class="text-end small opacity-75"><div id="clock"></div></div>
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
          <div class="small text-muted mt-1">.log, .txt, .gz, .zip, .docx, .pdf, .xlsx 등 다중 선택 가능</div>
          <input type="file" id="fileInput" multiple accept=".log,.gz,.txt,.audit,.json,.zip,.tar,.tgz,.docx,.pdf,.xlsx,.xls,.xlsm,.xml"
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
          <div id="desc-excess" class="mt-1"><strong>&#128200; 과다조회:</strong> 일별(≥500)/시간당(≥100) 임계값 초과, 대량 조회(BULK), 대상 다양성, 최근 30일 평균 대비 추세 급증</div>
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
                <option value="db">DB 감사 로그 (Oracle/MySQL/MSSQL)</option>
                <option value="postgresql">PostgreSQL 로그</option>
                <option value="web">웹 접근 로그 (Apache/Nginx)</option>
                <option value="app">앱 로그 (Log4j/Syslog)</option>
                <option value="generic">범용 (비정형)</option>
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

  <!-- 시작 안내 카드 (분석 전에만 표시) -->
  <div id="section-welcome">
    <div class="welcome-card mb-4">
      <div class="d-flex align-items-center mb-3 gap-2">
        <span style="font-size:1.6rem">&#128272;</span>
        <div>
          <div class="fw-bold fs-5" style="color:#1F4E79">시스템 소개</div>
          <div class="small text-muted">DB·웹·앱 로그를 분석해 개인정보 오남용 및 과다조회를 자동 탐지하고 소명 근거를 생성합니다.</div>
        </div>
      </div>
      <div class="row g-3 mb-3">
        <div class="col-md-6">
          <div class="welcome-feature">
            <span class="welcome-icon">&#128196;</span>
            <div>
              <div class="fw-bold small">지원 로그 형식</div>
              <div class="small text-muted">MySQL · Oracle · MSSQL · <strong>PostgreSQL</strong> · Apache/Nginx · Log4j · Syslog · 비정형 텍스트</div>
            </div>
          </div>
          <div class="welcome-feature">
            <span class="welcome-icon">&#128269;</span>
            <div>
              <div class="fw-bold small">지원 파일 확장자</div>
              <div class="small text-muted"><code>.log</code> · <code>.txt</code> · <code>.gz</code> · <code>.zip</code> · <code>.tar.gz</code> · <code>.docx</code> · <code>.pdf</code> · <code>.xlsx</code> · <code>.xml</code> · <code>.audit</code> · <code>.json</code> &nbsp;·&nbsp; 형식 자동 감지 · 압축/문서 자동 처리</div>
            </div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="welcome-feature">
            <span class="welcome-icon">&#128274;</span>
            <div>
              <div class="fw-bold small">탐지 개인정보 항목</div>
              <div class="small text-muted">주민번호 · 전화번호 · 신용카드 · 계좌번호 · 이메일 · 여권번호 · 이름 · 주소 · 생년월일 · 사원번호</div>
            </div>
          </div>
          <div class="welcome-feature">
            <span class="welcome-icon">&#128202;</span>
            <div>
              <div class="fw-bold small">출력 보고서</div>
              <div class="small text-muted">Excel 7시트 (소명 양식 포함) + HTML 보고서 · 위험 점수 자동 산정</div>
            </div>
          </div>
        </div>
      </div>

      <!-- 빠른 사용 절차 -->
      <div class="fw-bold small mb-2" style="color:#1F4E79">&#9654; 빠른 사용 절차</div>
      <div class="d-flex flex-wrap gap-2 align-items-center small">
        <span class="badge rounded-pill" style="background:#1F4E79">1 로그 파일 업로드</span>
        <span class="text-muted">&#8594;</span>
        <span class="badge rounded-pill" style="background:#1F4E79">2 분석 기간 설정</span>
        <span class="text-muted">&#8594;</span>
        <span class="badge rounded-pill" style="background:#1F4E79">3 점검 항목 선택</span>
        <span class="text-muted">&#8594;</span>
        <span class="badge rounded-pill bg-success">4 점검 시작</span>
        <span class="text-muted">&#8594;</span>
        <span class="badge rounded-pill bg-warning text-dark">5 보고서 다운로드</span>
      </div>
      <div class="mt-2 text-end">
        <button class="btn btn-sm btn-outline-primary"
                data-bs-toggle="modal" data-bs-target="#helpModal">
          &#9432; 상세 안내 보기 (지원 형식 · 탐지 항목)
        </button>
      </div>
    </div>
  </div>

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

<!-- ══ 도움말 모달 ══════════════════════════════════════════ -->
<div class="modal fade help-modal" id="helpModal" tabindex="-1">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">

      <div class="modal-header" style="background:#1F4E79;color:white">
        <h5 class="modal-title">&#9432; 사용 안내 &amp; 탐지 항목 설명</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>

      <div class="modal-body p-0">
        <!-- 탭 네비게이션 -->
        <ul class="nav nav-tabs px-3 pt-3" id="helpTabs">
          <li class="nav-item">
            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab-howto">
              &#128218; 사용 방법
            </button>
          </li>
          <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-formats">
              &#128196; 지원 로그 형식
            </button>
          </li>
          <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-pii">
              &#128272; 탐지 개인정보 항목
            </button>
          </li>
          <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-findings">
              &#128200; 위반 유형 &amp; 임계값
            </button>
          </li>
        </ul>

        <div class="tab-content p-3 pt-2">

          <!-- ── 탭1: 사용 방법 ── -->
          <div class="tab-pane fade show active" id="tab-howto">
            <div class="row g-3 mt-1">
              <div class="col-md-6">
                <div class="guide-step">
                  <div class="d-flex align-items-center mb-1">
                    <span class="step-num">1</span>
                    <strong>로그 파일 업로드</strong>
                  </div>
                  <div class="small text-muted">
                    드래그&amp;드롭 또는 클릭하여 로그 파일을 선택합니다.<br>
                    여러 파일을 동시에 업로드할 수 있습니다.<br>
                    서버에 이미 있는 파일은 경로를 직접 입력하거나 <code>*.log</code> 형태의 glob 패턴을 사용합니다.
                  </div>
                  <div class="mt-2 p-2 rounded small" style="background:#f0f4ff">
                    <strong>지원 확장자:</strong>
                    <code>.log</code> <code>.txt</code> <code>.gz</code> <code>.zip</code> <code>.tar.gz</code> <code>.docx</code> <code>.pdf</code> <code>.xlsx</code> <code>.xls</code> <code>.xml</code> <code>.audit</code> <code>.json</code>
                    <br><strong>압축 해제:</strong> .zip / .tar.gz / .tgz 업로드 시 내부 파일 자동 추출
                    <br><strong>문서 처리:</strong> Word(.docx) · PDF · Excel(.xlsx/.xls) · XML — 텍스트 자동 추출 후 PII 탐지
                    <br><strong>크기 제한:</strong> 파일당 500 MB (대용량은 gzip/zip 압축 권장)
                  </div>
                </div>

                <div class="guide-step">
                  <div class="d-flex align-items-center mb-1">
                    <span class="step-num">2</span>
                    <strong>분석 기간 설정</strong>
                  </div>
                  <div class="small text-muted">
                    시작일과 종료일을 선택합니다.<br>
                    빠른 선택 버튼으로 최근 7일 / 30일 / 90일 / 이번 달을 한 번에 지정할 수 있습니다.<br>
                    로그 라인의 타임스탬프가 없거나 파싱 실패 시 해당 라인도 포함됩니다.
                  </div>
                </div>

                <div class="guide-step">
                  <div class="d-flex align-items-center mb-1">
                    <span class="step-num">3</span>
                    <strong>점검 항목 선택</strong>
                  </div>
                  <div class="small text-muted">
                    <strong>개인정보 오남용:</strong> SELECT 절에서 PII 컬럼 노출, 야간/업무시간 외 개인정보 조회, 단일 쿼리 대량 레코드 반환<br>
                    <strong>과다조회:</strong> 일별(≥500) / 시간당(≥100) 쿼리 임계값 초과, 대량 내보내기(BULK), 다수 대상 반복 조회, 최근 30일 평균 대비 10% 초과 시 추세 급증 탐지<br>
                    둘 다 선택 권장 (기본값)
                  </div>
                </div>
              </div>

              <div class="col-md-6">
                <div class="guide-step">
                  <div class="d-flex align-items-center mb-1">
                    <span class="step-num">4</span>
                    <strong>고급 설정 (선택)</strong>
                  </div>
                  <div class="small text-muted">
                    <strong>최소 위험 등급:</strong> LOW(전체) / MEDIUM 이상 / HIGH 이상 / CRITICAL 만 — 보고서에 포함할 사용자 범위 제한<br>
                    <strong>로그 형식:</strong> 기본 <em>자동 감지</em>. 감지 실패 시 명시적으로 지정<br>
                    &nbsp;&nbsp;- DB 감사: Oracle/MySQL/MSSQL<br>
                    &nbsp;&nbsp;- PostgreSQL: PostgreSQL 표준/CSV/pgaudit<br>
                    &nbsp;&nbsp;- 범용(비정형): 구조 없는 텍스트, .txt 로그<br>
                    &nbsp;&nbsp;- 문서 파일(.docx/.pdf/.xlsx/.xml): 항상 범용 파서로 자동 처리<br>
                    <strong>보고서 형식:</strong> HTML + Excel 동시 생성 권장
                  </div>
                </div>

                <div class="guide-step">
                  <div class="d-flex align-items-center mb-1">
                    <span class="step-num">5</span>
                    <strong>결과 확인 및 보고서 다운로드</strong>
                  </div>
                  <div class="small text-muted">
                    분석 완료 후 사용자별 위험 현황 테이블이 표시됩니다.<br>
                    <strong>소명 요청 우선순위</strong> 섹션에서 즉시 조사가 필요한 사용자를 확인합니다.<br>
                    <em>소명 근거 상세</em> 버튼으로 위반 증거·질문 목록을 조회합니다.<br>
                    Excel 보고서는 소명 요청 양식(서명란 포함)이 포함된 7개 시트로 구성됩니다.
                  </div>
                </div>

                <div class="p-3 rounded" style="background:#fff8e1;border:1px solid #ffd54f">
                  <div class="fw-bold small mb-1">&#9888; 주의사항</div>
                  <ul class="small text-muted mb-0 ps-3">
                    <li>로그에 실제 개인정보가 포함된 경우 보고서는 <strong>마스킹(*)처리</strong>됩니다.</li>
                    <li>노출량 수치는 SQL 분석 기반 <strong>추정값</strong>입니다. 정확한 확인은 DB 감사 로그 원본 또는 DLP 솔루션을 사용하세요.</li>
                    <li>코드 수정 후에는 반드시 <code>python web_app.py</code> 를 재실행하세요.</li>
                  </ul>
                </div>
              </div>
            </div>
          </div><!-- /tab-howto -->

          <!-- ── 탭2: 지원 로그 형식 ── -->
          <div class="tab-pane fade" id="tab-formats">
            <div class="row g-3 mt-1">

              <!-- MySQL -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#e8f5e9">
                    <strong>&#128200; MySQL General Query Log</strong>
                    <span class="badge bg-secondary ms-2">자동 감지</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">파서: <code>DbAccessParser</code> &nbsp;|&nbsp; 추출: timestamp, thread_id→user, SQL, Rows_sent</div>
                    <div class="log-example">2024-01-15T14:23:01.000000Z  12 Query  SELECT name, phone FROM customers
2024-01-15T14:23:01.000100Z  12 Query  SELECT * FROM members LIMIT 5000
2024-01-15T14:23:00.999Z     12 Connect  admin@localhost on mydb</div>
                  </div>
                </div>
              </div>

              <!-- PostgreSQL -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#e3f2fd">
                    <strong>&#128200; PostgreSQL Server Log</strong>
                    <span class="badge bg-primary ms-2">신규 지원</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">파서: <code>DbAccessParser</code> &nbsp;|&nbsp; 추출: timestamp, [pid] user@db, SQL (statement/duration/execute)</div>
                    <div class="log-example">2024-01-15 14:23:01.123 UTC [12345] admin@mydb LOG:  statement: SELECT name, phone FROM members
2024-01-15 14:23:02.456 UTC [12345] admin@mydb LOG:  duration: 50.12 ms  statement: SELECT * FROM customers
2024-01-15 23:05:00.001 UTC [99999] audit@hr LOG:  AUDIT: SESSION,1,1,READ,SELECT,,,"SELECT rrn FROM employees"</div>
                    <div class="small text-muted mt-1">PostgreSQL CSV 형식도 지원 (<code>log_destination = 'csvlog'</code>)</div>
                  </div>
                </div>
              </div>

              <!-- Oracle -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#fce4ec">
                    <strong>&#128200; Oracle Audit Trail</strong>
                    <span class="badge bg-secondary ms-2">자동 감지</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">파서: <code>DbAccessParser</code> &nbsp;|&nbsp; 추출: DB USER, SQL TEXT, ROWS_PROCESSED (멀티라인 블록)</div>
                    <div class="log-example">ACTION : 3
DB USER : "ADMIN"
OBJ NAME : "CUSTOMERS"
TIMESTAMP : 2024-01-15 14:23:01
SQL TEXT : SELECT CUST_NAME, PHONE FROM CUSTOMERS WHERE ID=123
ROWS_PROCESSED : 1847
RETURNCODE: 0</div>
                  </div>
                </div>
              </div>

              <!-- MSSQL -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#f3e5f5">
                    <strong>&#128200; MSSQL Audit Log</strong>
                    <span class="badge bg-secondary ms-2">자동 감지</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">파서: <code>DbAccessParser</code> &nbsp;|&nbsp; 추출: LoginName, StatementText, DatabaseName</div>
                    <div class="log-example">2024-01-15 14:23:01 AuditLog
LoginName: domain\hong
DatabaseName: CustomerDB
StatementText: SELECT TOP 1000 name, phone, address FROM dbo.Members
RowsAffected: 1000</div>
                  </div>
                </div>
              </div>

              <!-- Apache/Nginx -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#fff8e1">
                    <strong>&#127760; Apache / Nginx Access Log</strong>
                    <span class="badge bg-secondary ms-2">자동 감지</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">파서: <code>WebAccessParser</code> &nbsp;|&nbsp; 추출: IP, user, HTTP method, URL 경로·파라미터</div>
                    <div class="log-example">192.168.1.10 - hong [15/Jan/2024:14:23:01 +0900] "GET /api/member?name=홍길동&phone=01012345678 HTTP/1.1" 200 1234
10.0.0.5 - admin [15/Jan/2024:23:05:00 +0900] "POST /export/members HTTP/1.1" 200 98765</div>
                  </div>
                </div>
              </div>

              <!-- Log4j / App -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#e8eaf6">
                    <strong>&#128196; 앱 로그 (Log4j / Python / Syslog)</strong>
                    <span class="badge bg-secondary ms-2">자동 감지</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">파서: <code>AppLogParser</code> &nbsp;|&nbsp; 추출: timestamp, level, user_id, 쿼리·액션</div>
                    <div class="log-example">2024-01-15 14:23:01,123 INFO  [worker-1] MemberService - user=hong query=SELECT name,phone FROM members WHERE id=123 1847건 반환
2024-01-15 23:10:00.001 - auth.service - WARNING - user=kim 업무외시간 개인정보 조회 phone=010-1234-5678</div>
                  </div>
                </div>
              </div>

              <!-- 비정형 -->
              <div class="col-md-12">
                <div class="card">
                  <div class="card-header py-2" style="background:#f1f8e9">
                    <strong>&#128196; 비정형 텍스트 로그 (.txt 포함)</strong>
                    <span class="badge bg-success ms-2">자동 감지 + 직접 PII 스캔</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">파서: <code>GenericParser</code> &nbsp;|&nbsp; SQL 키워드 없이 숫자 패턴(전화번호·주민번호·카드번호)으로 직접 탐지</div>
                    <div class="row">
                      <div class="col-md-6">
                        <div class="log-example">2024-01-15 10:00:01 user001 조회: 홍길동 010-1234-5678 서울 강남구
2024-01-15 10:01:30 user002 record 800101-1234567 exported
접근로그: 192.168.1.1 admin 5555-1234-5678-9012 card_access</div>
                      </div>
                      <div class="col-md-6 small text-muted ps-md-3 pt-2">
                        <strong>탐지 조건:</strong><br>
                        • SQL 키워드 없어도 숫자 패턴 존재 시 PII 스캔 실행<br>
                        • 전화번호: <code>010-XXXX-XXXX</code> 형태<br>
                        • 주민번호: <code>YYMMDD-NNNNNNN</code> 체크섬 검증<br>
                        • 카드번호: 16자리 Luhn 검증<br>
                        • <strong>자동 감지 실패 시</strong> 로그 형식을 <em>범용(비정형)</em>으로 수동 지정
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- ── 문서 파일 섹션 구분선 ── -->
              <div class="col-12 mt-2">
                <div class="p-2 rounded text-center fw-bold small" style="background:#e8eaf6;color:#283593;letter-spacing:.05em">
                  &#128196; 문서 파일 — 텍스트 자동 추출 후 동일한 PII 탐지 파이프라인 적용
                </div>
              </div>

              <!-- Word -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#e3f2fd">
                    <strong>&#128196; Word 문서 (.docx)</strong>
                    <span class="badge bg-primary ms-2">v2.0 신규</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">추출 엔진: <code>python-docx</code> &nbsp;|&nbsp; 단락 텍스트 + 표(Table) 셀 값 추출</div>
                    <div class="log-example">&#128196; 개인정보 취급 대장
고객 A  주민번호: 800101-1000008  전화: 010-3456-7890
고객 B  카드번호: 4111-1111-1111-1111
&#9474; 성명  &#9474; 전화번호      &#9474;  (표 셀도 탐지)
&#9474; 홍길동&#9474; 010-1111-2222 &#9474;</div>
                    <div class="small text-muted mt-1">
                      • 단락 단위 라인 추출 후 PII 정규식 스캔<br>
                      • 표 내부 셀: 행 단위로 탭 구분 합산 → 스캔
                    </div>
                  </div>
                </div>
              </div>

              <!-- PDF -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#fce4ec">
                    <strong>&#128196; PDF 파일 (.pdf)</strong>
                    <span class="badge bg-primary ms-2">v2.0 신규</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">추출 엔진: <code>pdfplumber</code> &nbsp;|&nbsp; 페이지별 텍스트 레이아웃 유지 추출</div>
                    <div class="log-example">접근 이력 보고서 2024-03-15
사용자: emp007  시각: 22:45  DB: custdb
쿼리: SELECT rrn, name FROM personal_info
결과: 800101-1000008  홍길동  010-3456-7890</div>
                    <div class="small text-muted mt-1">
                      • 각 페이지 텍스트를 줄 단위로 분리 후 스캔<br>
                      • 스캔된 PDF(이미지형)는 텍스트 추출 불가 — OCR 미지원
                    </div>
                  </div>
                </div>
              </div>

              <!-- Excel -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#e8f5e9">
                    <strong>&#128196; Excel 파일 (.xlsx / .xls)</strong>
                    <span class="badge bg-primary ms-2">v2.0 신규</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">추출 엔진: <code>openpyxl</code> &nbsp;|&nbsp; 시트별 행 → 탭 구분 텍스트 변환</div>
                    <div class="log-example">[Sheet: DB접근로그]
타임스탬프           사용자   쿼리                                    건수
2024-03-15 10:30:00  emp003   SELECT name, phone, rrn FROM customers  120
2024-03-15 22:45:00  emp007   SELECT * FROM personal_info             3200</div>
                    <div class="small text-muted mt-1">
                      • 셀 값(직접 PII) + SQL 컬럼 분석 모두 적용<br>
                      • 시트명을 컨텍스트 헤더로 삽입하여 파서에 전달<br>
                      • .xlsm (매크로 포함) 도 지원
                    </div>
                  </div>
                </div>
              </div>

              <!-- XML -->
              <div class="col-md-6">
                <div class="card h-100">
                  <div class="card-header py-2" style="background:#fff8e1">
                    <strong>&#128196; XML 파일 (.xml)</strong>
                    <span class="badge bg-primary ms-2">v2.0 신규</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="small text-muted mb-1">추출 엔진: <code>xml.etree.ElementTree</code> &nbsp;|&nbsp; 요소 텍스트 + 속성값 구조화 추출</div>
                    <div class="log-example">&lt;event timestamp="2024-03-15 22:45" user="emp007"&gt;
  &lt;query&gt;SELECT rrn, name FROM personal_info&lt;/query&gt;
  &lt;rowsAffected&gt;3&lt;/rowsAffected&gt;
&lt;/event&gt;
&lt;rrn&gt;800101-1000008&lt;/rrn&gt;
&lt;phone&gt;010-3456-7890&lt;/phone&gt;</div>
                    <div class="small text-muted mt-1">
                      • 자식 요소 속성을 한 줄로 합성 → SQL 컬럼 분석 적용<br>
                      • 리프 요소 텍스트 개별 추출 → 직접 PII 값 탐지<br>
                      • 네임스페이스(<code>{http://...}tag</code>) 자동 제거
                    </div>
                  </div>
                </div>
              </div>

              <!-- 압축 파일 -->
              <div class="col-md-12">
                <div class="card">
                  <div class="card-header py-2" style="background:#f3e5f5">
                    <strong>&#128230; 압축 파일 (.zip / .tar.gz / .tgz)</strong>
                    <span class="badge bg-primary ms-2">v2.0 신규</span>
                  </div>
                  <div class="card-body pb-2">
                    <div class="row">
                      <div class="col-md-6">
                        <div class="small text-muted mb-1">업로드 시 서버에서 자동 압축 해제 → 내부 파일 각각을 개별 분석 대상으로 등록</div>
                        <div class="small mt-2">
                          <strong>지원 형식:</strong><br>
                          <code>.zip</code> &nbsp;·&nbsp; <code>.tar.gz</code> &nbsp;·&nbsp; <code>.tgz</code> &nbsp;·&nbsp; <code>.tar.bz2</code><br><br>
                          <strong>내부 파일 필터:</strong> <code>.log .txt .gz .csv .json .audit .docx .pdf .xlsx .xml</code> 만 추출<br>
                          이미지·실행파일 등 비로그 파일은 자동 제외
                        </div>
                      </div>
                      <div class="col-md-6 small text-muted ps-md-3 pt-1">
                        <strong>보안 처리:</strong><br>
                        • 경로 순회(Path Traversal) 공격 차단<br>
                        &nbsp;&nbsp;압축 해제 경로가 업로드 폴더 밖으로 벗어나면 해당 항목 제외<br><br>
                        <strong>활용 예시:</strong><br>
                        • 여러 서버의 로그를 zip으로 묶어 한 번에 업로드<br>
                        • 대용량 로그를 gzip 압축하여 전송 후 자동 해제 분석
                      </div>
                    </div>
                  </div>
                </div>
              </div>

            </div>
          </div><!-- /tab-formats -->

          <!-- ── 탭3: 탐지 개인정보 항목 ── -->
          <div class="tab-pane fade" id="tab-pii">

            <!-- ══ 탐지 처리 흐름 ══ -->
            <div class="row g-3 mt-1 mb-3">
              <div class="col-lg-5">
                <div class="fw-bold mb-2" style="color:#1F4E79">&#128270; 탐지 처리 흐름 (scan_event)</div>
                <div class="flow-wrap small">

                  <!-- Step 0: 파일 입력 분기 -->
                  <div class="flow-step" style="background:#ede7f6;border:1.5px solid #7e57c2">
                    <div class="d-flex align-items-center gap-1">
                      <span class="step-badge" style="background:#512da8">IN</span>
                      <strong>파일 입력</strong>
                    </div>
                    <div class="text-muted ms-4" style="font-size:.76rem">
                      <span class="flow-inline-code">.log/.txt/.gz</span> → 라인 스트리밍<br>
                      <span class="flow-inline-code">.zip/.tar.gz</span> → 압축 해제 후 내부 파일<br>
                      <span class="flow-inline-code">.docx/.pdf/.xlsx/.xml</span> → 텍스트 추출 (<code>doc_extractor</code>)
                    </div>
                  </div>
                  <div class="flow-arrow">&#8595;</div>

                  <!-- Step 0b: 로그 라인 -->
                  <div class="flow-step flow-step-main">
                    <div class="d-flex align-items-center gap-1">
                      <span class="step-badge">0</span>
                      <strong>로그 라인 파싱</strong>
                    </div>
                    <div class="text-muted ms-4" style="font-size:.76rem">
                      <span class="flow-inline-code">query_text</span> 우선,
                      없으면 <span class="flow-inline-code">raw_line</span> 사용
                    </div>
                  </div>
                  <div class="flow-arrow">&#8595;</div>

                  <!-- Step 1: 한글 숫자 -->
                  <div class="flow-step flow-step-warn">
                    <div class="d-flex align-items-center gap-1">
                      <span class="step-badge">1</span>
                      <strong>한글 숫자 감지 &amp; 변환</strong>
                    </div>
                    <div class="ms-4" style="font-size:.76rem; color:#555">
                      한글 숫자 3글자+ 있으면<br>
                      <span class="flow-inline-code">_convert_hangul_numbers()</span> 실행<br>
                      &nbsp;&nbsp;공백 제거 + 하이픈 유지 + 한글→아라비아
                    </div>
                  </div>
                  <div class="flow-arrow">&#8595;</div>

                  <!-- Step 2: quick filter -->
                  <div class="flow-step" style="background:#f3e5f5;border:1.5px solid #c77dca">
                    <div class="d-flex align-items-center gap-1">
                      <span class="step-badge" style="background:#7b1fa2">2</span>
                      <strong>빠른 키워드 필터</strong>
                      <span class="badge bg-secondary ms-1" style="font-size:.68rem">성능 최적화</span>
                    </div>
                    <div class="ms-4" style="font-size:.76rem;color:#555">
                      변환본 기준으로 SQL/PII 키워드 검사<br>
                      <span class="flow-inline-code">select · phone · 이름 · 주민 · account</span> 등 35개
                    </div>
                  </div>

                  <!-- 분기 화살표 -->
                  <div class="d-flex mt-1 mb-1" style="gap:.5rem;font-size:.75rem">
                    <div class="d-flex flex-column align-items-center" style="flex:1">
                      <span style="color:#28a745">&#10003; 키워드 있음</span>
                      <span style="color:#28a745;font-size:1rem">&#8595;</span>
                    </div>
                    <div class="d-flex flex-column align-items-center" style="flex:1">
                      <span style="color:#dc3545">&#10007; 키워드 없음</span>
                      <span style="color:#dc3545;font-size:1rem">&#8595;</span>
                    </div>
                  </div>

                  <div class="d-flex gap-2">
                    <!-- 키워드 있음 경로 -->
                    <div style="flex:1">
                      <div class="flow-step flow-step-ok" style="font-size:.75rem;padding:.5rem .7rem">
                        스캔 진행
                      </div>
                    </div>
                    <!-- 키워드 없음 경로 -->
                    <div style="flex:1">
                      <div class="flow-step flow-step-warn" style="font-size:.75rem;padding:.5rem .7rem">
                        <strong>Step 3</strong> 로그 유형 확인<br>
                        <span style="color:#28a745">비정형</span>: 숫자 패턴 직접 검사<br>
                        <span style="color:#dc3545">구조화</span>: &#9888; 스킵
                      </div>
                    </div>
                  </div>
                  <div class="flow-arrow">&#8595;</div>

                  <!-- Step 4: 스캔 -->
                  <div class="flow-step" style="background:#e3f2fd;border:1.5px solid #64b5f6">
                    <div class="d-flex align-items-center gap-1">
                      <span class="step-badge" style="background:#1565c0">4</span>
                      <strong>PII 패턴 스캔 (이중 스캔)</strong>
                    </div>
                    <div class="ms-4" style="font-size:.76rem;color:#555">
                      ① <strong>원본 텍스트</strong> 스캔 (아라비아 숫자 PII)<br>
                      ② <strong>한글 변환본</strong> 스캔 (한글 숫자 PII)<br>
                      &nbsp;&nbsp;주민번호 → 체크섬 검증<br>
                      &nbsp;&nbsp;카드번호 → Luhn 알고리즘 검증
                    </div>
                  </div>
                  <div class="flow-arrow">&#8595;</div>

                  <!-- Step 5: 결과 -->
                  <div class="flow-step flow-step-final">
                    <div class="d-flex align-items-center gap-1">
                      <span class="step-badge" style="background:#c0392b">OUT</span>
                      <strong>PiiHit 목록 반환</strong>
                    </div>
                    <div class="ms-4" style="font-size:.76rem;color:#555">
                      중복 제거: <span class="flow-inline-code">(PII유형, 마스킹값)</span> 기준<br>
                      원본·변환본 합산 후 Finding 생성
                    </div>
                  </div>

                </div><!-- /flow-wrap -->
              </div><!-- /col-lg-5 -->

              <!-- 우측: 비정형 로그 경로 상세 -->
              <div class="col-lg-7">
                <div class="fw-bold mb-2" style="color:#1F4E79">&#128196; 로그 유형별 스캔 진입 조건</div>
                <table class="table table-bordered table-sm small mb-3">
                  <thead>
                    <tr><th>로그 유형</th><th>파서</th><th>키워드 없을 때 처리</th><th>비고</th></tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><span class="badge" style="background:#1F4E79">db</span></td>
                      <td>DbAccessParser</td>
                      <td><span class="text-danger">스킵</span></td>
                      <td>SQL 키워드 항상 포함 — 스킵 거의 발생 안 함</td>
                    </tr>
                    <tr>
                      <td><span class="badge" style="background:#1F4E79">web</span></td>
                      <td>WebAccessParser</td>
                      <td><span class="text-danger">스킵</span></td>
                      <td>URL 파라미터에 PII 키워드 포함 시 통과</td>
                    </tr>
                    <tr class="table-warning">
                      <td><span class="badge bg-warning text-dark">app</span></td>
                      <td>AppLogParser</td>
                      <td><span class="text-success">숫자 패턴 검사</span></td>
                      <td>앱 로그는 SQL 키워드 없을 수 있음 → 전화번호·주민번호·카드 패턴으로 2차 확인</td>
                    </tr>
                    <tr class="table-warning">
                      <td><span class="badge bg-success">unknown</span></td>
                      <td>GenericParser</td>
                      <td><span class="text-success">숫자 패턴 검사</span></td>
                      <td>비정형 .txt 등 — 직접 숫자 패턴 검사</td>
                    </tr>
                    <tr class="table-warning">
                      <td><span class="badge bg-secondary">generic</span></td>
                      <td>GenericParser</td>
                      <td><span class="text-success">숫자 패턴 검사</span></td>
                      <td>범용 폴백 — 숫자 패턴 검사</td>
                    </tr>
                    <tr style="background:#ede7f6">
                      <td><span class="badge" style="background:#512da8">docx/pdf</span></td>
                      <td>GenericParser</td>
                      <td><span class="text-success">숫자 패턴 검사</span></td>
                      <td>doc_extractor로 텍스트 추출 후 GenericParser 적용 — 직접 PII 탐지</td>
                    </tr>
                    <tr style="background:#ede7f6">
                      <td><span class="badge" style="background:#512da8">xlsx/xml</span></td>
                      <td>GenericParser</td>
                      <td><span class="text-success">숫자 패턴 검사</span></td>
                      <td>행/요소 단위 텍스트 추출 → 직접 PII + SQL 컬럼 분석 모두 적용</td>
                    </tr>
                  </tbody>
                </table>

                <div class="fw-bold mb-2" style="color:#1F4E79">&#9889; 숫자 패턴 2차 검사 기준 (비정형 전용)</div>
                <div class="p-2 rounded small mb-3" style="background:#f8f9fa;border:1px solid #dee2e6">
                  아래 3가지 중 하나라도 매칭되면 전체 PII 스캔 진행:
                  <div class="mt-2 font-monospace" style="font-size:.78rem;line-height:2">
                    <span class="badge bg-primary me-1">전화번호</span>
                    <code>0X0[-\s]?\d{3,4}[-\s]?\d{4}</code>
                    &nbsp; 예: <code>010-1234-5678</code><br>
                    <span class="badge bg-primary me-1">주민번호</span>
                    <code>\d{6}[-\s]?[1-4]\d{6}</code>
                    &nbsp; 예: <code>800101-1234567</code><br>
                    <span class="badge bg-primary me-1">카드번호</span>
                    <code>(\d{4}[-\s]?){3}\d{4}</code>
                    &nbsp; 예: <code>4111-1111-1111-1111</code>
                  </div>
                  <div class="text-muted mt-1" style="font-size:.75rem">
                    &#8251; 한글 숫자는 아라비아로 변환 후 위 패턴으로 검사
                  </div>
                </div>

                <div class="fw-bold mb-2" style="color:#e65100">&#127373; PII 키워드 목록 (Quick Filter — 35개)</div>
                <div class="p-2 rounded" style="background:#fff3e0;border:1px solid #ffcc80;font-size:.76rem;line-height:1.9">
                  <span class="fw-bold text-muted">SQL:</span>
                  <code>select · query · insert · update · where</code><br>
                  <span class="fw-bold text-muted">영문 PII:</span>
                  <code>name · phone · address · email · account · acct · card · ssn · rrn · birth · passport · empno · cust · member · personal</code><br>
                  <span class="fw-bold text-muted">한글 PII:</span>
                  <code>이름 · 전화 · 주민 · 계좌 · 주소 · 생년 · 고객 · 회원 · 개인 · 여권 · 사원번호 · 접속</code><br>
                  <span class="fw-bold text-muted">IP 관련:</span>
                  <code>ip · addr · client · remote · src_ip · 접속</code>
                </div>
              </div>
            </div><!-- /row -->

            <hr class="my-2">
            <div class="small text-muted mb-2">
              아래 표: <strong>raw_line</strong> 전체 + 추출된 <strong>query_text</strong> 모두를 스캔합니다.
              주민번호는 날짜+체크섬, 신용카드는 Luhn 알고리즘으로 오탐을 추가 검증합니다.
            </div>
            <div class="table-responsive">
              <table class="table table-bordered table-sm align-middle">
                <thead>
                  <tr>
                    <th>유형</th><th>위험도</th><th>탐지 패턴 (예시)</th><th>탐지 예시</th><th>마스킹 출력</th>
                  </tr>
                </thead>
                <tbody>
                  <tr class="pii-row-CRITICAL">
                    <td><strong>주민등록번호</strong><br><code class="small">RRN</code></td>
                    <td><span class="badge badge-CRITICAL">CRITICAL</span></td>
                    <td class="small font-monospace">YYMMDD[-]NNNNNNN<br>(체크섬 검증)</td>
                    <td class="small"><code>800101-1234567</code><br><code>8001011234567</code></td>
                    <td class="small"><code>80****-*******</code></td>
                  </tr>
                  <tr class="pii-row-CRITICAL">
                    <td><strong>신용카드번호</strong><br><code class="small">CREDIT_CARD</code></td>
                    <td><span class="badge badge-CRITICAL">CRITICAL</span></td>
                    <td class="small font-monospace">4자리×4 그룹<br>(Luhn 검증)</td>
                    <td class="small"><code>4111-1111-1111-1111</code><br><code>4111111111111111</code></td>
                    <td class="small"><code>4111-****-****-1111</code></td>
                  </tr>
                  <tr class="pii-row-CRITICAL">
                    <td><strong>계좌번호</strong><br><code class="small">ACCOUNT_NO</code></td>
                    <td><span class="badge badge-CRITICAL">CRITICAL</span></td>
                    <td class="small font-monospace">계좌/account/bankno<br>선행 키워드 + 10-14자리</td>
                    <td class="small"><code>account_no=1234567890123</code><br><code>계좌: 110-1234-5678</code></td>
                    <td class="small"><code>123****890</code></td>
                  </tr>
                  <tr class="pii-row-HIGH">
                    <td><strong>전화번호</strong><br><code class="small">PHONE</code></td>
                    <td><span class="badge badge-HIGH">HIGH</span></td>
                    <td class="small font-monospace">010/02/0X[-]XXXX[-]XXXX</td>
                    <td class="small"><code>010-1234-5678</code><br><code>0212345678</code></td>
                    <td class="small"><code>010-****-5678</code></td>
                  </tr>
                  <tr class="pii-row-HIGH">
                    <td><strong>여권번호</strong><br><code class="small">PASSPORT</code></td>
                    <td><span class="badge badge-HIGH">HIGH</span></td>
                    <td class="small font-monospace">한국식: [A-Z][A-Z0-9]XXXXXXX</td>
                    <td class="small"><code>M12345678</code><br><code>AB1234567</code></td>
                    <td class="small"><code>M1*****78</code></td>
                  </tr>
                  <tr class="pii-row-HIGH">
                    <td><strong>이름</strong><br><code class="small">NAME_IN_QUERY</code></td>
                    <td><span class="badge badge-HIGH">HIGH</span></td>
                    <td class="small font-monospace">name/이름/고객명=<br>한국어 2-4자</td>
                    <td class="small"><code>name='홍길동'</code><br><code>고객명=이순신</code></td>
                    <td class="small"><code>홍**</code></td>
                  </tr>
                  <tr class="pii-row-HIGH">
                    <td><strong>생년월일</strong><br><code class="small">BIRTHDATE</code></td>
                    <td><span class="badge badge-HIGH">HIGH</span></td>
                    <td class="small font-monospace">birth/생년월일/dob=<br>YYYY-MM-DD</td>
                    <td class="small"><code>birth='1990-01-15'</code><br><code>dob=19900115</code></td>
                    <td class="small"><code>1990-**-**</code></td>
                  </tr>
                  <tr class="pii-row-MEDIUM">
                    <td><strong>이메일</strong><br><code class="small">EMAIL</code></td>
                    <td><span class="badge badge-MEDIUM">MEDIUM</span></td>
                    <td class="small font-monospace">user@domain.tld</td>
                    <td class="small"><code>hong@company.com</code></td>
                    <td class="small"><code>ho***@company.com</code></td>
                  </tr>
                  <tr class="pii-row-MEDIUM">
                    <td><strong>주소</strong><br><code class="small">ADDRESS</code></td>
                    <td><span class="badge badge-MEDIUM">MEDIUM</span></td>
                    <td class="small font-monospace">시/도/구+동/읍/로+번지</td>
                    <td class="small"><code>서울시 강남구 테헤란로 123</code></td>
                    <td class="small"><code>서울시 강남**번지</code></td>
                  </tr>
                  <tr class="pii-row-MEDIUM">
                    <td><strong>사원번호</strong><br><code class="small">EMP_ID_IN_QUERY</code></td>
                    <td><span class="badge badge-MEDIUM">MEDIUM</span></td>
                    <td class="small font-monospace">
                      키워드 선행 필수:<br>
                      <code>emp_id · 사번 · 사원번호</code><br>
                      <code>employee_id · empno</code><br>
                      <code>staff_id · staff_no</code><br>
                      값 형태: 숫자(12345) /<br>
                      영문+숫자(EMP003, K-12345)
                    </td>
                    <td class="small">
                      <code>emp_id=12345</code><br>
                      <code>사번: K-12345</code><br>
                      <code>employee_id: 9876543</code><br>
                      <code>staff_id=A0012345</code>
                    </td>
                    <td class="small"><code>em*****45</code><br><code>사번***45</code></td>
                  </tr>
                  <tr>
                    <td><strong>IP 주소</strong><br><code class="small">IP_ADDRESS</code></td>
                    <td><span class="badge" style="background:#6c757d">LOW</span></td>
                    <td class="small font-monospace">IPv4: 0-255 점4개<br>IPv6: 16진수:콜론<br>루프백·브로드캐스트 제외</td>
                    <td class="small"><code>192.168.1.55</code><br><code>10.0.5.200</code><br><code>2001:db8::1</code></td>
                    <td class="small"><code>192.168.1.**</code><br><code>10.0.5.***</code><br><code>2001:db8:****</code></td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="mt-2 p-3 rounded small" style="background:#f0f4ff">
              <strong>SQL SELECT 절 PII 컬럼 탐지</strong>
              (실효 노출량 = 결과 건수 × PII 컬럼 수):
              <span class="font-monospace">
                name · cust_name · phone · mobile · tel · email · address · rrn · ssn · jumin ·
                birthdate · dob · account_no · card_no · passport · emp_id
              </span>
              등 30+ 컬럼명 인식
            </div>

            <!-- ══ 한글 숫자 변환 규칙 상세 ══ -->
            <div class="mt-3 p-3 rounded border border-warning" style="background:#fffde7">
              <div class="fw-bold mb-3" style="color:#e65100;font-size:1rem">
                &#127373; 한글 숫자 표기 자동 탐지 규칙 (_convert_hangul_numbers)
              </div>

              <div class="row g-3 small">
                <!-- 좌: 매핑표 + 변환 규칙 -->
                <div class="col-md-4">
                  <div class="fw-bold mb-1">문자 매핑</div>
                  <table class="table table-bordered table-sm mb-2" style="font-size:.8rem">
                    <thead><tr><th>한글</th><th>아라비아</th><th>한글</th><th>아라비아</th></tr></thead>
                    <tbody>
                      <tr><td><code>영</code> / <code>공</code></td><td class="fw-bold text-primary">0</td><td><code>육</code></td><td class="fw-bold text-primary">6</td></tr>
                      <tr><td><code>일</code></td><td class="fw-bold text-primary">1</td><td><code>칠</code></td><td class="fw-bold text-primary">7</td></tr>
                      <tr><td><code>이</code></td><td class="fw-bold text-primary">2</td><td><code>팔</code></td><td class="fw-bold text-primary">8</td></tr>
                      <tr><td><code>삼</code></td><td class="fw-bold text-primary">3</td><td><code>구</code></td><td class="fw-bold text-primary">9</td></tr>
                      <tr><td><code>사</code></td><td class="fw-bold text-primary">4</td><td colspan="2" class="text-muted" style="font-size:.72rem">10개 문자 지원</td></tr>
                      <tr><td><code>오</code></td><td class="fw-bold text-primary">5</td><td colspan="2"></td></tr>
                    </tbody>
                  </table>
                  <div class="p-2 rounded" style="background:#fff3e0;border:1px solid #ffcc80;font-size:.76rem;line-height:1.8">
                    <div class="fw-bold mb-1">변환 규칙</div>
                    <div>&#10004; 한글 숫자 → 아라비아 숫자</div>
                    <div>&#10004; 중간 공백 (스페이스·탭·다중공백) → <strong>제거</strong></div>
                    <div>&#10004; 하이픈(-) → <strong>그대로 유지</strong></div>
                    <div>&#10004; 최소 3글자 이상 시퀀스에만 적용</div>
                    <div>&#10004; 변환 후 체크섬·Luhn 검증 동일 적용</div>
                    <div class="text-muted mt-1">&#9888; 십·백·천·만 위치기수법 미지원<br>(자릿수 표기는 각 숫자 직접 표기)</div>
                  </div>
                </div>

                <!-- 우: 변환 예시 코드 블록 -->
                <div class="col-md-8">
                  <div class="fw-bold mb-1">변환 예시 (탐지 규칙)</div>
                  <div class="hangul-rule-box">
<span class="hr-note"># ── 전화번호: 하이픈 구분 ──────────────────────</span>
<span class="hr-in">공일공-일이삼사-오육칠팔</span>
<span class="hr-arr">  →</span> <span class="hr-out">010-1234-5678</span>  <span class="hr-tag">[PHONE 탐지]</span>

<span class="hr-note"># ── 전화번호: 공백 포함 (공백 제거 후 조합) ────</span>
<span class="hr-in">공 일 공 일 이 삼 사 오 육 칠 팔</span>
<span class="hr-arr">  →</span> <span class="hr-out">01012345678</span>      <span class="hr-tag">[PHONE 탐지]</span>

<span class="hr-note"># ── 전화번호: 다중 공백 포함 ───────────────────</span>
<span class="hr-in">공  일  공  일  이  삼  사  오  육  칠  팔</span>
<span class="hr-arr">  →</span> <span class="hr-out">01012345678</span>      <span class="hr-tag">[PHONE 탐지]</span>

<span class="hr-note"># ── 혼합: 앞부분 아라비아 + 뒷부분 한글 ────────</span>
<span class="hr-in">010-일이삼사-오육칠팔</span>
<span class="hr-arr">  →</span> <span class="hr-out">010-1234-5678</span>  <span class="hr-tag">[PHONE 탐지]</span>

<span class="hr-note"># ── 주민번호 (변환 후 체크섬 검증) ─────────────</span>
<span class="hr-in">팔공일이삼사-일이삼사오육칠</span>
<span class="hr-arr">  →</span> <span class="hr-out">801234-1234567</span> <span class="hr-tag">[RRN 후보 → 체크섬 검증]</span>

<span class="hr-note"># ── 카드번호 (변환 후 Luhn 검증) ───────────────</span>
<span class="hr-in">사일일일-일일일일-일일일일-일일일일</span>
<span class="hr-arr">  →</span> <span class="hr-out">4111-1111-1111-1111</span> <span class="hr-tag">[CARD → Luhn 통과 시 탐지]</span>

<span class="hr-note"># ── 비정형 로그 (키워드 없음) ──────────────────</span>
<span class="hr-in">사용자 공일공일이삼사오육칠팔 야간접속</span>
<span class="hr-arr">  →</span> <span class="hr-out">사용자 01012345678 야간접속</span>
<span class="hr-arr">  →</span> <span class="hr-tag">숫자패턴 2차검사 → PHONE 탐지</span>

<span class="hr-note"># ── SQL + 한글 숫자 ─────────────────────────────</span>
<span class="hr-in">SELECT phone FROM t WHERE p='공일공-일이삼사-오육칠팔'</span>
<span class="hr-arr">  →</span> <span class="hr-out">SELECT phone FROM t WHERE p='010-1234-5678'</span>
<span class="hr-arr">  →</span> <span class="hr-tag">키워드(phone·select) → PHONE 탐지</span></div>
                </div>
              </div>
            </div>
          </div><!-- /tab-pii -->

          <!-- ── 탭4: 위반 유형 & 임계값 ── -->
          <div class="tab-pane fade" id="tab-findings">
            <div class="row g-3 mt-1">

              <div class="col-md-6">
                <div class="fw-bold mb-2" style="color:#8B0000">&#128274; 오남용(MISUSE) 탐지 항목</div>
                <table class="table table-bordered table-sm threshold-table">
                  <thead><tr><th>카테고리</th><th>탐지 기준</th><th>위험도</th></tr></thead>
                  <tbody>
                    <tr>
                      <td><strong>PII_EXPOSURE</strong><br><small>개인정보 노출</small></td>
                      <td class="small">SQL SELECT 절에 PII 컬럼 포함<br>or 로그 라인에서 직접 PII 패턴 매칭<br><span class="text-muted">예) SELECT ssn, name FROM members</span></td>
                      <td><span class="badge badge-CRITICAL">CRITICAL</span>~<span class="badge badge-MEDIUM">MEDIUM</span></td>
                    </tr>
                    <tr>
                      <td><strong>PII_RECORD_EXPOSURE</strong><br><small>대량 레코드 노출</small></td>
                      <td class="small">실효 노출량(건수×PII컬럼):<br>
                        &ge;1,000: MEDIUM / &ge;10,000: HIGH / &ge;50,000: CRITICAL<br>
                        <span class="text-muted">예) SELECT ssn, phone FROM customers → 결과 8,000건<br>&nbsp;&nbsp;&nbsp;&nbsp;→ 실효 노출량 16,000 (HIGH)</span></td>
                      <td><span class="badge badge-CRITICAL">CRITICAL</span>~<span class="badge badge-MEDIUM">MEDIUM</span></td>
                    </tr>
                    <tr>
                      <td><strong>AFTER_HOURS</strong><br><small>업무외시간 조회</small></td>
                      <td class="small">업무시간(08:00~19:00) 외 PII 조회 5건 초과 시<br><span class="text-muted">예) 23:15에 주민번호 포함 쿼리 6회 실행</span></td>
                      <td><span class="badge badge-HIGH">HIGH</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div class="col-md-6">
                <div class="fw-bold mb-2" style="color:#fd7e14">&#128200; 과다조회(EXCESS) 탐지 항목</div>
                <table class="table table-bordered table-sm threshold-table">
                  <thead><tr><th>카테고리</th><th>탐지 기준</th><th>위험도</th></tr></thead>
                  <tbody>
                    <tr>
                      <td><strong>EXCESSIVE_ACCESS</strong><br><small>과다 쿼리</small></td>
                      <td class="small">일별 쿼리: &ge;500 경고 / &ge;2,000 위험<br>시간당: &ge;100 경고 / &ge;500 위험<br><span class="text-muted">예) hong 계정이 하루 1,523건 쿼리 실행<br>&nbsp;&nbsp;&nbsp;&nbsp;→ 일별 조회 건수 1,523건 (임계값: 500건)</span></td>
                      <td><span class="badge badge-CRITICAL">CRITICAL</span>~<span class="badge badge-HIGH">HIGH</span></td>
                    </tr>
                    <tr>
                      <td><strong>BULK_EXPORT</strong><br><small>대량 내보내기</small></td>
                      <td class="small">LIMIT/TOP/ROWNUM &ge;1,000 건<br>or SELECT * FROM &lt;테이블&gt; (WHERE 없음)<br>하루 3건 초과 시 경고<br><span class="text-muted">예) SELECT * FROM members LIMIT 5000<br>&nbsp;&nbsp;&nbsp;&nbsp;→ 하루 대량 조회 4건 (임계값: 3건)</span></td>
                      <td><span class="badge badge-HIGH">HIGH</span></td>
                    </tr>
                    <tr>
                      <td><strong>EXCESSIVE_ACCESS</strong><br><small>고유 대상 다양성</small></td>
                      <td class="small">하루 서로 다른 대상 &ge;50명(건) 접근 시 경고<br><span class="text-muted">예) 하루 동안 71명의 고객 정보를 개별 조회<br>&nbsp;&nbsp;&nbsp;&nbsp;→ 하루 고유 대상 71개 (임계값: 50개)</span></td>
                      <td><span class="badge badge-MEDIUM">MEDIUM</span></td>
                    </tr>
                    <tr>
                      <td><strong>EXCESSIVE_ACCESS</strong><br><small>일별 추세 급증</small></td>
                      <td class="small"><strong>사용자별</strong> 당일 조회 건수가 해당 사용자의 최근 30일 평균 대비 10% 초과<br>(50% 초과 시 HIGH, 최소 7일 이력 필요)<br><span class="text-muted">예) hong 계정: 본인 30일 평균 80건 → 당일 350건<br>&nbsp;&nbsp;&nbsp;&nbsp;→ hong의 평균 대비 337.5% 초과 → HIGH 탐지</span></td>
                      <td><span class="badge badge-HIGH">HIGH</span>~<span class="badge badge-MEDIUM">MEDIUM</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div class="col-12">
                <div class="fw-bold mb-2" style="color:#1F4E79">&#128202; 위험 점수 산정 기준 (합계 100점 기준)</div>
                <div class="table-responsive">
                  <table class="table table-bordered table-sm threshold-table">
                    <thead><tr><th>요소</th><th>가중치</th><th>설명</th></tr></thead>
                    <tbody>
                      <tr><td>PII 접촉 (CRITICAL)</td><td>25%</td><td>CRITICAL 등급 PII 탐지 건수 기반</td></tr>
                      <tr><td>PII 접촉 (HIGH)</td><td>20%</td><td>HIGH 등급 PII 탐지 건수 기반</td></tr>
                      <tr><td>과다조회 (일별)</td><td>20%</td><td>일별 최대 쿼리 수 임계값 대비 비율</td></tr>
                      <tr><td>과다조회 (시간당)</td><td>15%</td><td>시간당 최대 쿼리 수 임계값 대비 비율</td></tr>
                      <tr><td>야간 PII 조회</td><td>5%</td><td>업무시간 외 PII 조회 건수</td></tr>
                      <tr><td>대량 내보내기</td><td>5%</td><td>BULK_EXPORT 탐지 건수</td></tr>
                    </tbody>
                  </table>
                </div>

                <div class="fw-bold mb-2 mt-2" style="color:#8B0000">&#128203; 소명 우선순위(priority_score) 산정</div>
                <div class="table-responsive">
                  <table class="table table-bordered table-sm threshold-table">
                    <thead><tr><th>항목</th><th>점수</th><th>urgency 기준</th></tr></thead>
                    <tbody>
                      <tr><td>단일 쿼리 대량 노출</td><td>+55점</td><td rowspan="7" class="align-middle">
                        <span class="badge" style="background:#8B0000">즉시</span> &ge;100점<br>
                        <span class="badge badge-HIGH">긴급</span> &ge;60점<br>
                        <span class="badge" style="background:#1F4E79">검토</span> &lt;60점<br><br>
                        CRITICAL 등급 ×1.25 보정
                      </td></tr>
                      <tr><td>총 PII 노출량 초과</td><td>+40점</td></tr>
                      <tr><td>야간 PII 조회</td><td>+40점</td></tr>
                      <tr><td>일별 과다조회</td><td>+30점</td></tr>
                      <tr><td>시간별 과다조회</td><td>+20점</td></tr>
                      <tr><td>대량 조회</td><td>+20점</td></tr>
                      <tr><td>PII 다양성</td><td>+15점</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          </div><!-- /tab-findings -->

        </div><!-- tab-content -->
      </div><!-- modal-body -->

      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
      </div>
    </div>
  </div>
</div><!-- /helpModal -->

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
  document.getElementById('section-welcome').style.display = 'none';
  document.getElementById('section-progress').style.display = 'block';
  document.getElementById('section-results').style.display = 'none';
  document.getElementById('progressLog').textContent = '';
  document.getElementById('progressBar').style.width = '0%';
  document.getElementById('prog-msg').textContent = '요청 전송 중...';
  document.getElementById('prog-pct').textContent = '0%';

  // ★ 버그3 수정: 전송 직후 file input 초기화 → 같은 파일명 재선택 시 change 이벤트 발생
  fileInput.value = '';

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
  document.getElementById('btnStart').disabled = false;   // ★ 버그1 수정: 완료 후 버튼 재활성화
  document.getElementById('section-progress').style.display = 'none';
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
  document.getElementById('section-welcome').style.display = 'block';
  document.getElementById('btnStart').disabled = false;
  document.getElementById('progressBar').style.width = '0%';
  document.getElementById('progressBar').classList.add('progress-bar-animated');
  document.getElementById('progressBar').classList.remove('bg-danger');
  if (dtInstance) { dtInstance.destroy(); dtInstance = null; }
  currentJobId = null;
  if (pollTimer) clearTimeout(pollTimer);
  // ★ 버그2 수정: 파일 선택 상태 초기화
  selectedFiles = [];
  document.getElementById('fileList').innerHTML = '';
  fileInput.value = '';   // 같은 파일 재선택 가능하게
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
