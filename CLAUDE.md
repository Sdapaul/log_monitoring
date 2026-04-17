# 개인정보 오남용·과다조회 점검 시스템

DB/웹/앱 로그를 분석해 개인정보 오남용·과다조회를 탐지하고 소명 근거를 생성하는 Flask 기반 시스템.

## 파일 구조

```
main.py                        # CLI 진입점
web_app.py                     # Flask 웹 UI (http://localhost:5000)
config.py                      # THRESHOLDS 등 설정
pipeline/runner.py             # 공유 분석 파이프라인
parsers/auto_detector.py       # 로그 포맷 자동 감지
detectors/sql_clause_analyzer.py  # effective_pii_exposure = result_rows × PII_field_count
models/user_summary.py         # total_pii_records_exposed, max_single_query_exposure
reports/excel_reporter.py      # 7시트 Excel
reports/html_reporter.py       # Bootstrap5 HTML
reports/justification_builder.py  # 소명 우선순위 생성
history/manager.py             # 스냅샷 저장·이력 비교
```

## 분석 파이프라인

로그파일 → 파서(자동감지) → LogEvent → PII탐지+SQL분석 → AccessCounter 집계 → UserSummary → 선택필터 → score_all → 이력비교 → 보고서(Excel+HTML) → build_justification_list

## Finding 카테고리

- **오남용(MISUSE):** PII_EXPOSURE, AFTER_HOURS, PII_RECORD_EXPOSURE
- **과다조회(EXCESS):** EXCESSIVE_ACCESS, BULK_EXPORT

## 웹 앱 주요 라우트

| 라우트 | 설명 |
|---|---|
| `GET /` | 메인 UI |
| `POST /api/analyze` | 분석 시작, job_id 반환 |
| `GET /api/status/<job_id>` | 진행률 폴링 |
| `GET /api/download/<job_id>/<fmt>` | xlsx/html 다운로드 |

분석 파라미터: `start_date`, `end_date`, `log_files[]`, `check_misuse`, `check_excess`, `min_risk_level`, `log_format`, `report_formats[]`

## Excel 보고서 7시트

1. 요약 — 전체 통계
2. 사용자별 현황
3. 개인정보 검출 상세
4. SQL 분석 상세
5. 소명 요청 양식 (JustificationItem 기반)
6. 소명 증거 상세 (마스킹 증적)
7. 비교 분석 (1주/1개월 전)

## 소명(JustificationItem) priority_score 기준

단일쿼리 대량노출(55) + 총노출량(40) + 야간PII조회(40) + 일별과다조회(30) + 시간별과다조회(20) + 대량조회(20) + PII다양성(15), CRITICAL ×1.25  
urgency: 즉시(≥100) / 긴급(≥60) / 검토(<60)

## 주의사항

- **서버 재시작 필수:** 코드 수정 후 `python web_app.py` 재실행. 미재시작 시 justification_items가 빈 배열 반환.
- **Windows CP949:** `print()`에 이모지 사용 금지 (UnicodeEncodeError). HTML/Excel 내부는 UTF-8 사용 가능.
- **최신 보고서 파일:** `glob` 알파벳순 말고 `os.path.getmtime` 기준 최신 파일 선택.
- **백그라운드 스레드 예외:** 결과 이상 시 `/api/status/<job_id>` error 필드 확인.
