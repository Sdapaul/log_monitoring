# 개인정보 오남용·과다조회 점검 시스템

DB/웹/앱 로그 분석 → PII 탐지 → 소명 근거 생성. Flask 기반.

## 분석 대상 파일 및 내용

### 입력 로그 파일 (sample_logs/ 또는 업로드)
| 파일/형식 | 파서 | 추출 내용 |
|---|---|---|
| MySQL General Log (`*.log`) | `DbAccessParser` | timestamp, thread_id→user, SQL, Rows_sent |
| Oracle Audit Trail | `DbAccessParser` | DB USER, ACTION, SQL TEXT, ROWS_PROCESSED |
| MSSQL Audit Log | `DbAccessParser` | LoginName, StatementText, DatabaseName |
| PostgreSQL Server Log (`*.log`, `*.txt`) | `DbAccessParser` | timestamp, [pid] user@db, LOG statement/duration/execute, pgaudit |
| PostgreSQL CSV Log | `DbAccessParser` | timestamp, user, db, client_addr, message |
| Apache/Nginx Access Log | `WebAccessParser` | IP, user, method, path, URL params |
| Log4j/앱 로그 | `AppLogParser` | timestamp, level, user_id, 쿼리/액션 |
| 기타 CSV/텍스트 (`*.txt`, `*.csv`) | `GenericParser` | 정규식으로 timestamp·user·쿼리 추출; 비정형도 숫자 패턴(전화/주민/카드)으로 PII 탐지 |

### 탐지하는 PII 종류 (`config.py → PII_PATTERNS`)
`RRN`(주민번호) · `PHONE` · `ACCOUNT_NO` · `CREDIT_CARD` · `PASSPORT` · `EMAIL` · `NAME_IN_QUERY` · `ADDRESS` · `EMP_ID_IN_QUERY` · `EMP_ID_STANDALONE` · `BIRTHDATE` · `IP_ADDRESS`

### 핵심 분석 지표
- **effective_pii_exposure** = result_row_count × PII_select_field_count  
- **exposure_type**: FULL_EXPOSURE / PARTIAL_EXPOSURE / SEARCH_ONLY / NONE  
- 임계값: `THRESHOLDS` (max_queries_per_day=500, bulk_select_row_threshold=1000 등)

## 파일 구조

```
config.py                        # PII_PATTERNS, THRESHOLDS, LOG_FORMAT_SIGNATURES
main.py                          # CLI 진입점
web_app.py                       # Flask UI (http://localhost:5000)
parsers/auto_detector.py         # 로그 포맷 자동 감지 (특이성 점수 기반)
parsers/base_parser.py           # 파서 공통 기반 클래스
parsers/{db,web,app,generic}_*   # 파서 4종 (DB/Web/App/Generic)
detectors/pii_detector.py        # 정규식 스캔 + 한글숫자 변환 + RRN체크섬 + Luhn 검증
detectors/sql_clause_analyzer.py # SELECT/WHERE PII 컬럼 분석, 결과건수 파싱
detectors/access_counter.py      # 시간·일별 쿼리 집계
detectors/anomaly_scorer.py      # score_all → risk_score, risk_level
models/log_event.py              # LogEvent + PiiHit (파싱 결과)
models/finding.py                # Finding (탐지 결과)
models/user_summary.py           # UserSummary (사용자별 집계)
pipeline/runner.py               # 핵심 파이프라인 (process_file → score_all → 보고서)
pipeline/stream_reader.py        # 파일 스트리밍, .gz 해제, 문서 파일 라우팅
pipeline/doc_extractor.py        # Word/PDF/Excel/PPTX/XML 텍스트 추출
pipeline/aggregator.py           # 사용자별 UserSummary 집계, Finding 생성
reports/excel_reporter.py        # 7시트 Excel
reports/html_reporter.py         # Bootstrap5 HTML (CSS/JS 인라인 내장)
reports/justification_builder.py # JustificationItem + priority_score
history/manager.py               # JSON 스냅샷 저장·이력 비교·delta 계산
history/daily_counts.py          # 일별 쿼리 수 추세 데이터 누적 저장·로드
utils/date_utils.py              # 날짜 파싱, 분석 범위 내 날짜 여부 판단
```

## 파이프라인 흐름

```
로그/문서 파일
  → stream_reader.stream_lines()          # .gz 해제, 문서 파일 분기
      ├─ 텍스트/CSV/로그 → detect_format → parser.parse_line → LogEvent
      └─ 문서(.docx/.pdf/.xlsx/.xml) → doc_extractor.extract_lines() → GenericParser → LogEvent
  → scan_event(PII) + analyze_sql         # pii_hits, exposure_type, result_row_count
  → AccessCounter.add                     # 시간·일별 집계
  → build_user_summaries → UserSummary
  → score_all → risk_score / risk_level
  → save_snapshot + compute_deltas        # history/*.json
  → save_daily_counts                     # history/daily_counts 추세 저장
  → generate_excel + generate_html
  → build_justification_list → JustificationItem[]
```

## Finding 카테고리

- **오남용(MISUSE):** `PII_EXPOSURE`, `AFTER_HOURS`, `PII_RECORD_EXPOSURE`
- **과다조회(EXCESS):** `EXCESSIVE_ACCESS`, `BULK_EXPORT`

## 웹 API

| 라우트 | 설명 |
|---|---|
| `POST /api/analyze` | 분석 시작 → job_id |
| `GET /api/status/<job_id>` | 진행률 폴링 (error 필드 확인) |
| `GET /api/download/<job_id>/<fmt>` | xlsx/html 다운로드 |
| `GET /api/jobs` | 전체 Job 목록 조회 |

파라미터: `start_date`, `end_date`, `log_files[]`, `check_misuse`, `check_excess`, `min_risk_level`, `log_format`, `report_formats[]`

## 소명 priority_score

단일쿼리대량노출(55)+총노출량(40)+야간PII(40)+일별과다(30)+시간별과다(20)+대량조회(20)+PII다양성(15), CRITICAL×1.25  
urgency: 즉시(≥100) / 긴급(≥60) / 검토(<60)

## 주의사항

- **서버 재시작 필수:** 코드 수정 후 `python web_app.py` 재실행 (미재시작 시 justification_items 빈 배열)
- **Windows CP949:** `print()`에 이모지 금지 (UnicodeEncodeError). HTML/Excel 내부는 UTF-8 가능
- **최신 보고서:** `glob` 알파벳순 아닌 `os.path.getmtime` 기준으로 파일 선택
- **백그라운드 예외:** 이상 시 `/api/status/<job_id>` `error` 필드 확인
