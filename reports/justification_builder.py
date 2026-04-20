"""
소명 요청 우선순위 및 근거 생성 모듈
- 누구에게 소명을 요청할지 우선순위 결정
- 구체적인 위반 이유 생성
- 실제 화면에 표시된 것으로 추정되는 내용 설명
- 소명 질문 목록 생성
"""
from __future__ import annotations
from dataclasses import dataclass, field
from models.user_summary import UserSummary
from models.finding import Finding
from config import THRESHOLDS

CATEGORY_KR = {
    'PII_EXPOSURE':       '개인정보 노출',
    'AFTER_HOURS':        '업무외시간 조회',
    'BULK_EXPORT':        '대량 조회',
    'EXCESSIVE_ACCESS':   '과다조회',
    'PII_RECORD_EXPOSURE': '단일 대량 개인정보 노출',
}

SEVERITY_KR = {
    'CRITICAL': '최고위험',
    'HIGH':     '고위험',
    'MEDIUM':   '중위험',
    'LOW':      '저위험',
}

PII_FIELD_KR = {
    'name': '이름', 'cust_name': '고객명', 'customer_name': '고객명',
    'phone': '전화번호', 'tel': '전화번호',
    'email': '이메일', 'mail': '이메일',
    'address': '주소', 'addr': '주소',
    'rrn': '주민등록번호', 'ssn': '주민등록번호', 'jumin': '주민등록번호',
    'birthdate': '생년월일', 'birth': '생년월일', 'dob': '생년월일',
    'account': '계좌번호', 'account_no': '계좌번호', 'bankno': '계좌번호',
    'card': '카드번호', 'card_no': '카드번호',
    'passport': '여권번호',
    'gender': '성별', 'sex': '성별',
    'nationality': '국적',
    'salary': '급여', 'income': '소득',
}


def _pii_fields_to_kr(fields: list[str]) -> str:
    """PII 컬럼 목록을 한국어로 변환합니다."""
    kr = [PII_FIELD_KR.get(f.lower(), f) for f in fields]
    # 중복 제거, 순서 유지
    seen, out = set(), []
    for k in kr:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return ', '.join(out) if out else '개인정보 컬럼'


@dataclass
class JustificationItem:
    """소명 요청 대상자 1명의 소명 근거 패키지"""
    priority_rank: int
    user_id: str
    risk_score: float
    risk_level: str
    priority_score: float
    urgency: str                           # '즉시', '긴급', '검토'

    reasons: list[str] = field(default_factory=list)         # 위반 이유 목록
    screen_estimate: str = ''                                 # 화면 노출 추정 설명
    key_findings: list[dict] = field(default_factory=list)   # 핵심 증거 (직렬화 완료)
    questions: list[str] = field(default_factory=list)        # 소명 질문 목록
    summary_one_line: str = ''                                # 한 줄 요약 (이메일 제목용)

    def to_dict(self) -> dict:
        return {
            'priority_rank':  self.priority_rank,
            'user_id':        self.user_id,
            'risk_score':     self.risk_score,
            'risk_level':     self.risk_level,
            'priority_score': self.priority_score,
            'urgency':        self.urgency,
            'reasons':        self.reasons,
            'screen_estimate': self.screen_estimate,
            'key_findings':   self.key_findings,
            'questions':      self.questions,
            'summary_one_line': self.summary_one_line,
        }


def build_justification_list(summaries: list[UserSummary]) -> list[JustificationItem]:
    """
    소명 요청 대상자 목록을 우선순위 순으로 생성합니다.
    CRITICAL/HIGH 등급 사용자를 대상으로 하며, '소명 필요도'를 별도로 산정합니다.
    """
    items = []
    candidates = [s for s in summaries if s.risk_level in ('CRITICAL', 'HIGH', 'MEDIUM')]

    for s in candidates:
        priority_score = _compute_priority_score(s)
        urgency = _urgency_label(priority_score)
        reasons = _generate_reasons(s)
        screen_est = _estimate_screen_content(s)
        key_findings = _select_key_findings_dict(s)
        questions = _generate_questions(s)
        summary = _one_line_summary(s, reasons)

        items.append(JustificationItem(
            priority_rank=0,
            user_id=s.user_id,
            risk_score=s.risk_score,
            risk_level=s.risk_level,
            priority_score=priority_score,
            urgency=urgency,
            reasons=reasons,
            screen_estimate=screen_est,
            key_findings=key_findings,
            questions=questions,
            summary_one_line=summary,
        ))

    items.sort(key=lambda x: x.priority_score, reverse=True)
    for i, item in enumerate(items, 1):
        item.priority_rank = i

    return items


# ── 내부 헬퍼 ─────────────────────────────────────────────

def _compute_priority_score(s: UserSummary) -> float:
    """
    소명 요청 우선순위 점수를 계산합니다.
    '위험도'가 아닌 '즉각 확인 필요성'을 기준으로 합니다.
    """
    score = 0.0

    # [A] 단일 쿼리 대량 노출 → 즉각 확인 (한 번에 수만 건 노출)
    if s.max_single_query_exposure >= 20_000:
        score += 55
    elif s.max_single_query_exposure >= 5_000:
        score += 35
    elif s.max_single_query_exposure >= 1_000:
        score += 15

    # [B] 기간 내 총 노출량
    if s.total_pii_records_exposed >= 100_000:
        score += 40
    elif s.total_pii_records_exposed >= 50_000:
        score += 30
    elif s.total_pii_records_exposed >= 10_000:
        score += 20
    elif s.total_pii_records_exposed >= 1_000:
        score += 8

    # [C] 야간 PII 조회 → 정당한 업무 사유 확인 필수
    if s.after_hours_count >= 20:
        score += 40
    elif s.after_hours_count >= 5:
        score += 25
    elif s.after_hours_count >= 1:
        score += 12

    # [D] 과다조회 (비정상적 반복 접근)
    thr_day = THRESHOLDS.get('max_queries_per_day', 500)
    thr_hr  = THRESHOLDS.get('max_queries_per_hour', 100)
    if s.max_queries_per_day >= thr_day * 4:
        score += 30
    elif s.max_queries_per_day >= thr_day * 2:
        score += 20
    elif s.max_queries_per_day >= thr_day:
        score += 8

    if s.max_queries_per_hour >= thr_hr * 4:
        score += 20
    elif s.max_queries_per_hour >= thr_hr:
        score += 10

    # [E] 대량 조회 (BULK)
    score += min(20, s.bulk_export_count * 5)

    # [F] PII 유형 다양성 (여러 종류 = 광범위 접근)
    score += min(15, len(s.pii_types_seen) * 4)

    # [G] 위험 등급 가중
    if s.risk_level == 'CRITICAL':
        score *= 1.25

    return round(score, 2)


def _urgency_label(priority_score: float) -> str:
    if priority_score >= 100:
        return '즉시'
    elif priority_score >= 60:
        return '긴급'
    else:
        return '검토'


def _generate_reasons(s: UserSummary) -> list[str]:
    """구체적 위반 이유를 생성합니다. 가장 중요한 이유부터 나열합니다."""
    reasons = []
    thr_day = THRESHOLDS.get('max_queries_per_day', 500)
    thr_hr  = THRESHOLDS.get('max_queries_per_hour', 100)
    biz_s   = THRESHOLDS.get('business_hours_start', 8)
    biz_e   = THRESHOLDS.get('business_hours_end', 19)

    # ① 단일 쿼리 대량 노출 (가장 중요)
    if s.max_single_query_exposure >= 20_000:
        reasons.append(
            f"[긴급] 단일 쿼리 1건에서 개인정보 {s.max_single_query_exposure:,}건 일시 노출 "
            f"— 의도적 대량 추출 또는 무단 반출 가능성"
        )
    elif s.max_single_query_exposure >= 5_000:
        reasons.append(
            f"단일 쿼리에서 개인정보 {s.max_single_query_exposure:,}건 반환 "
            f"(화면 또는 API 응답으로 노출된 것으로 추정)"
        )
    elif s.max_single_query_exposure >= 1_000:
        reasons.append(
            f"단일 쿼리에서 개인정보 {s.max_single_query_exposure:,}건 반환"
        )

    # ② 총 노출량
    if s.total_pii_records_exposed >= 10_000:
        reasons.append(
            f"점검 기간 내 이름·전화번호 등 개인정보가 포함된 쿼리를 "
            f"{s.select_pii_query_count:,}건 실행, "
            f"총 {s.total_pii_records_exposed:,}건의 개인정보 레코드 노출 추정"
        )
    elif s.total_pii_records_exposed >= 1_000:
        reasons.append(
            f"SELECT 절에 개인정보 컬럼을 포함한 쿼리 {s.select_pii_query_count:,}건 실행, "
            f"총 {s.total_pii_records_exposed:,}건 노출 추정"
        )

    # ③ 야간 조회
    if s.after_hours_count > 0:
        reasons.append(
            f"업무 시간({biz_s:02d}:00~{biz_e:02d}:00) 외 개인정보 조회 {s.after_hours_count:,}건 발생 "
            f"(개인정보보호법 시행령 제30조 접근권한 관리 위반 소지)"
        )

    # ④ 과다조회
    if s.max_queries_per_day >= thr_day:
        excess = s.max_queries_per_day - thr_day
        reasons.append(
            f"일별 최대 {s.max_queries_per_day:,}회 조회 — 정책 임계값({thr_day:,}회) 대비 "
            f"{excess:,}회 초과 (비정상 자동화 또는 반복 접근 의심)"
        )
    if s.max_queries_per_hour >= thr_hr:
        reasons.append(
            f"1시간 내 최대 {s.max_queries_per_hour:,}회 집중 조회 "
            f"(임계값 {thr_hr:,}회 초과 — 스크립트·매크로 사용 의심)"
        )

    # ⑤ 대량 조회
    if s.bulk_export_count > 0:
        reasons.append(
            f"대량 데이터 조회(BULK) {s.bulk_export_count:,}건 발생 "
            f"— 데이터 추출·외부 전송 가능성 확인 필요"
        )

    # ⑥ PII 유형 다양성
    if len(s.pii_types_seen) >= 3:
        pii_list = ', '.join(sorted(s.pii_types_seen))
        reasons.append(
            f"다양한 개인정보 유형({pii_list}) 접근 — 광범위 정보 수집 가능성"
        )

    # ⑦ Finding 기반 구체적 사례 (야간 AFTER_HOURS 최초 발생 건)
    for f in s.findings:
        if f.category == 'AFTER_HOURS' and f.details:
            hr   = f.details.get('hour', '')
            cnt  = f.details.get('count', '')
            date = f.details.get('date', '')
            if hr and date:
                reasons.append(
                    f"최초 야간 조회 사례: {date} {hr:02d}시경 개인정보 {cnt}건 조회 "
                    f"(참조: {f.raw_reference})"
                )
                break

    if not reasons:
        reasons.append(
            f"위험 점수 {s.risk_score:.1f}점 ({s.risk_level}) — "
            f"세부 내역은 아래 핵심 증거 참조"
        )
    return reasons


def _estimate_screen_content(s: UserSummary) -> str:
    """
    실제 화면에 표시되었을 것으로 추정되는 개인정보 내용을 설명합니다.

    [원리]
    SELECT 절에 이름·전화번호 등 PII 컬럼이 포함된 쿼리가 실행되면,
    DB가 반환한 레코드 수 × PII 컬럼 수 = 화면(또는 API 응답)으로
    전달된 개인정보 항목 수를 추정할 수 있습니다.
    """
    lines = []

    if s.total_pii_records_exposed == 0 and s.select_pii_query_count == 0:
        lines.append(
            "▶ 화면 직접 노출 추정 불가\n"
            "   검출된 개인정보가 주로 WHERE 절 검색 조건(예: 전화번호로 고객 검색)에 사용되었거나,\n"
            "   쿼리 결과 건수를 로그에서 확인할 수 없어 노출량을 정량화하기 어렵습니다.\n"
            "   단, 개인정보가 검색 키로 사용된 것 자체는 위반 소지가 있을 수 있습니다."
        )
        return '\n'.join(lines)

    # 노출 추정 설명
    lines.append("▶ 화면(또는 API 응답) 노출 추정")
    if s.select_pii_query_count > 0 and s.total_pii_records_exposed > 0:
        lines.append(
            f"   이름·전화번호·주소 등 개인정보 컬럼을 SELECT 절에 포함한 쿼리 "
            f"{s.select_pii_query_count:,}건이 실행되었으며,\n"
            f"   이 쿼리들이 반환한 결과 건수를 합산하면 총 {s.total_pii_records_exposed:,}건의 "
            f"개인정보 레코드가 화면 또는 응답으로 전달된 것으로 추정됩니다."
        )

    if s.max_single_query_exposure > 0:
        lines.append(
            f"\n   ※ 단일 조회 최대 노출: {s.max_single_query_exposure:,}건\n"
            f"      (한 번의 쿼리로 {s.max_single_query_exposure:,}명 분량의 개인정보가 한꺼번에 반환)"
        )

    if s.unknown_exposure_query_count > 0:
        lines.append(
            f"\n   ※ 결과 건수 확인 불가 쿼리 {s.unknown_exposure_query_count:,}건 추가 존재\n"
            f"      (로그에 결과 건수가 기록되지 않아 위 수치에 미포함 — 실제 노출량은 더 클 수 있음)"
        )

    lines.append(
        "\n▶ 실제 화면 내용을 정확히 확인하려면:\n"
        "   1) DB 감사 로그에서 해당 세션 ID의 쿼리 및 Rows_sent 확인\n"
        "   2) 애플리케이션 서버 로그에서 API 응답 내용 또는 화면 렌더링 데이터 확인\n"
        "   3) DB Performance Schema / Slow Query Log 상세 조회\n"
        "   4) DLP 솔루션 또는 네트워크 패킷 캡처 (민감정보 탐지 솔루션 연동 시)\n"
        "   ※ 본 보고서의 수치는 SELECT 쿼리 분석 기반 추정값입니다."
    )

    return '\n'.join(lines)


def _select_key_findings_dict(s: UserSummary) -> list[dict]:
    """소명에 가장 중요한 Finding 상위 5개를 직렬화하여 반환합니다."""
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    def sort_key(f: Finding):
        sev = sev_order.get(f.severity, 9)
        exp = -(f.details.get('effective_exposure') or 0) if f.details else 0
        return (sev, exp)

    top = sorted(s.findings, key=sort_key)[:5]

    result = []
    for f in top:
        details = f.details or {}
        pii_fields = details.get('pii_select_fields', [])
        exposure_type = details.get('exposure_type', '')
        result_rows = details.get('result_row_count')
        effective = details.get('effective_exposure')

        # 증거 한국어 요약
        if pii_fields:
            field_str = _pii_fields_to_kr(pii_fields)
            summary = f"[{CATEGORY_KR.get(f.category, f.category)}] {field_str} 컬럼 조회"
        else:
            summary = f"[{CATEGORY_KR.get(f.category, f.category)}] {f.pii_types_str}"

        if result_rows is not None and result_rows > 0:
            summary += f" — 결과 {result_rows:,}건 반환"
        if effective and effective > 0:
            summary += f" (노출 추정 {effective:,}건)"

        exposure_kr = {
            'FULL_EXPOSURE': '전체컬럼 노출(SELECT*)',
            'PARTIAL_EXPOSURE': 'PII컬럼 직접 출력',
            'SEARCH_ONLY': '검색조건만 사용',
        }.get(exposure_type, '')

        result.append({
            'finding_id':    f.finding_id,
            'category':      f.category,
            'category_kr':   CATEGORY_KR.get(f.category, f.category),
            'severity':      s.risk_level,
            'severity_kr':   SEVERITY_KR.get(s.risk_level, s.risk_level),
            'timestamp_str': f.timestamp_str,
            'pii_types_str': f.pii_types_str,
            'exposure_type_kr': exposure_kr,
            'result_rows':   result_rows,
            'effective_exposure': effective,
            'evidence':      (f.evidence or '')[:250],
            'raw_reference': f.raw_reference,
            'summary':       summary,
        })
    return result


def _generate_questions(s: UserSummary) -> list[str]:
    """소명 요청 시 사용자에게 질문할 항목을 생성합니다."""
    questions = []
    thr_day = THRESHOLDS.get('max_queries_per_day', 500)
    biz_s   = THRESHOLDS.get('business_hours_start', 8)
    biz_e   = THRESHOLDS.get('business_hours_end', 19)

    if s.total_pii_records_exposed >= 1_000 or s.select_pii_query_count > 0:
        questions.append(
            f"이름·전화번호 등 개인정보 컬럼이 포함된 쿼리를 점검 기간 내 "
            f"{s.select_pii_query_count:,}건 실행하셨습니다. "
            f"각 조회의 구체적인 업무 목적을 설명해 주세요."
        )

    if s.max_single_query_exposure >= 5_000:
        questions.append(
            f"단일 쿼리에서 {s.max_single_query_exposure:,}건의 개인정보를 한꺼번에 조회하셨습니다. "
            f"해당 조회가 필요했던 구체적 업무를 설명하고, 결과 데이터를 어떻게 활용하셨는지 "
            f"(화면 확인, 파일 저장, 외부 전송 여부) 답변해 주세요."
        )

    if s.after_hours_count > 0:
        questions.append(
            f"업무 시간({biz_s:02d}:00~{biz_e:02d}:00) 외에 개인정보를 포함한 조회가 "
            f"{s.after_hours_count:,}건 발생하였습니다. "
            f"야간·주말 조회가 필요했던 사유와 승인 여부를 설명해 주세요."
        )

    if s.max_queries_per_day >= thr_day:
        questions.append(
            f"하루 최대 {s.max_queries_per_day:,}회의 조회가 발생하였습니다. "
            f"단시간 내 대량 조회가 발생한 상황(자동화 스크립트 사용 여부, 특정 작업 수행 여부)을 "
            f"설명해 주세요."
        )

    if s.bulk_export_count > 0:
        questions.append(
            f"대량 데이터 조회가 {s.bulk_export_count:,}건 감지되었습니다. "
            f"데이터를 파일로 내려받거나 외부 시스템으로 전송하셨다면 "
            f"목적, 상대방, 현재 보관 방법을 알려주세요."
        )

    questions.append(
        "조회하신 개인정보를 업무 목적 외 용도로 활용하거나, "
        "외부로 반출(출력, 다운로드, 메신저·이메일 전송 등)하신 사례가 있으신가요? "
        "있다면 상세 내용을 기재해 주세요."
    )

    return questions


def _one_line_summary(s: UserSummary, reasons: list[str]) -> str:
    """소명 요청 이메일 제목 등에 사용할 한 줄 요약을 생성합니다."""
    parts = []
    if s.max_single_query_exposure >= 20_000:
        parts.append(f"단일 {s.max_single_query_exposure:,}건 노출")
    elif s.total_pii_records_exposed >= 10_000:
        parts.append(f"총 {s.total_pii_records_exposed:,}건 노출")
    if s.after_hours_count > 0:
        parts.append(f"야간 {s.after_hours_count}건")
    if s.max_queries_per_day >= THRESHOLDS.get('max_queries_per_day', 500):
        parts.append(f"일 {s.max_queries_per_day:,}회 과다조회")

    if parts:
        return f"{s.user_id}: " + ' / '.join(parts)
    elif reasons:
        return f"{s.user_id}: " + reasons[0][:60]
    return f"{s.user_id}: 위험 점수 {s.risk_score:.1f}점 ({s.risk_level})"
