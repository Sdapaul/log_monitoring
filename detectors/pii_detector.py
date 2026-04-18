"""
개인정보(PII) 탐지 엔진
- 정규식 패턴 매칭
- 한글 숫자 → 아라비아 숫자 정규화 (공일공-일이삼사-오육칠팔 → 010-1234-5678)
- 주민등록번호 체크섬 검증 (오탐 감소)
- 신용카드 Luhn 검증
- 보고서용 마스킹 처리
"""
from __future__ import annotations
import re
from config import COMPILED_PII, PII_TRIGGER_KEYWORDS
from models.log_event import LogEvent, PiiHit


# ── 비정형 로그용 숫자 패턴 (전화번호·주민번호·카드번호 후보) ─────────
_RAW_NUMBER_RE = re.compile(
    r'\b0(?:1[016-9]|2|[3-9]\d)[-\s]?\d{3,4}[-\s]?\d{4}\b'  # 전화번호
    r'|\b\d{6}[-\s]?[1-4]\d{6}\b'                             # 주민번호 후보
    r'|\b(?:\d{4}[-\s]?){3}\d{4}\b'                           # 카드번호 후보
)

# ── 한글 숫자 정규화 ──────────────────────────────────────────────────
# 한글 숫자 → 아라비아 숫자 매핑
HANGUL_DIGIT_MAP: dict[str, str] = {
    '영': '0', '공': '0',
    '일': '1', '이': '2', '삼': '3', '사': '4', '오': '5',
    '육': '6', '칠': '7', '팔': '8', '구': '9',
}
_HAN_DIGIT_SET: frozenset[str] = frozenset(HANGUL_DIGIT_MAP)
_HAN_DIGIT_CHARS: str = ''.join(_HAN_DIGIT_SET)

# 한글 숫자 시퀀스: 3글자 이상, 사이에 공백(여러 칸 포함)·하이픈 허용
# 예: "공일공-일이삼사-오육칠팔"  "공 일 공 일 이 삼 사 오 육 칠 팔"
_HAN_NUM_SEQ_RE = re.compile(
    r'[' + _HAN_DIGIT_CHARS + r']'
    r'(?:[ \t]*-?[ \t]*[' + _HAN_DIGIT_CHARS + r']){2,}'
)


def _has_hangul_digits(text: str) -> bool:
    """텍스트에 한글 숫자 문자가 3개 이상 있는지 빠른 체크 (O(n), 조기 종료)."""
    count = 0
    for ch in text:
        if ch in _HAN_DIGIT_SET:
            count += 1
            if count >= 3:
                return True
    return False


def _convert_hangul_numbers(text: str) -> str:
    """
    한글 숫자 시퀀스를 아라비아 숫자로 변환합니다.

    규칙:
    - 한글 숫자 → 대응 아라비아 숫자 (영/공→0, 일→1, … 구→9)
    - 시퀀스 내 공백은 제거 (중간 공백 포함)
    - 시퀀스 내 하이픈(-)은 유지

    예시:
      공일공-일이삼사-오육칠팔   →  010-1234-5678
      공 일 공 일 이 삼 사 오 육 칠 팔  →  01012345678
      팔공일이삼사-일이삼사오육칠 →  801234-1234567
      010-일이삼사-오육칠팔       →  010-1234-5678  (혼합 처리)
    """
    def _replace(m: re.Match) -> str:
        result = []
        for ch in m.group():
            if ch in HANGUL_DIGIT_MAP:
                result.append(HANGUL_DIGIT_MAP[ch])
            elif ch == '-':
                result.append('-')
            # 공백(space/tab)은 제거
        return ''.join(result)

    return _HAN_NUM_SEQ_RE.sub(_replace, text)


# ── quick filter ─────────────────────────────────────────────────────

def quick_filter(line: str) -> bool:
    """PII 패턴 실행 전 빠른 사전 필터 (약 3-5배 성능 향상)."""
    lower = line.lower()
    return any(kw in lower for kw in PII_TRIGGER_KEYWORDS)


# ── 핵심 스캔 함수 ────────────────────────────────────────────────────

def _scan_text(candidate: str) -> list[PiiHit]:
    """
    단일 텍스트에서 PII 패턴을 스캔하여 PiiHit 목록을 반환합니다.
    (원본/정규화본 양쪽에서 재사용하는 내부 함수)
    """
    hits: list[PiiHit] = []
    seen_spans: list[tuple[int, int]] = []

    for pii_type, (compiled_regex, severity) in COMPILED_PII.items():
        for match in compiled_regex.finditer(candidate):
            start, end = match.start(), match.end()

            # 이미 처리된 범위와 겹치면 스킵 (중복 방지)
            if any(s <= start < e or s < end <= e for s, e in seen_spans):
                continue

            matched_value = match.group()

            # 타입별 추가 유효성 검사 (오탐 감소)
            if pii_type == 'RRN':
                if not validate_rrn(matched_value):
                    continue
            elif pii_type == 'CREDIT_CARD':
                if not validate_luhn(matched_value):
                    continue
            elif pii_type == 'ACCOUNT_NO':
                if match.lastindex and match.lastindex >= 1:
                    matched_value = match.group(1)

            hits.append(PiiHit(
                pii_type=pii_type,
                severity=severity,
                redacted_value=redact_pii(matched_value, pii_type),
                match_start=start,
                match_end=end,
            ))
            seen_spans.append((start, end))

    return hits


def scan_event(event: LogEvent) -> list[PiiHit]:
    """
    LogEvent를 스캔하여 PII 히트 목록을 반환합니다.

    처리 순서:
    1. 한글 숫자 시퀀스 감지 → 아라비아 숫자로 정규화
       (공백 포함 연속 한글 숫자도 공백 제거 후 변환)
    2. 정규화본 기준으로 quick_filter / 숫자 패턴 체크
    3. 원본 + 정규화본 모두 PII 스캔, 중복 제거 후 합산
    """
    candidate = event.query_text or event.raw_line

    # ── 한글 숫자 정규화 ──────────────────────────────────
    normalized: str | None = None
    if _has_hangul_digits(candidate):
        converted = _convert_hangul_numbers(candidate)
        if converted != candidate:          # 실제로 변환이 일어난 경우만
            normalized = converted

    # quick_filter 는 정규화본 우선 적용
    scan_base = normalized if normalized else candidate

    if not quick_filter(scan_base):
        # 비정형/generic 로그: 숫자 패턴으로 2차 확인
        if event.log_type not in ('unknown', 'generic', 'app'):
            return []
        if not _RAW_NUMBER_RE.search(scan_base):
            return []

    # ── 스캔 실행 ─────────────────────────────────────────
    # (pii_type, redacted_value) 키로 중복 제거
    seen_keys: set[tuple[str, str]] = set()
    hits: list[PiiHit] = []

    def _add_hits(text: str) -> None:
        for hit in _scan_text(text):
            key = (hit.pii_type, hit.redacted_value)
            if key not in seen_keys:
                seen_keys.add(key)
                hits.append(hit)

    _add_hits(candidate)            # 원본 스캔 (아라비아 숫자 PII)
    if normalized:
        _add_hits(normalized)       # 정규화본 스캔 (한글 숫자 → 아라비아 변환 PII)

    return hits


# ── 유효성 검증 ───────────────────────────────────────────────────────

def validate_rrn(value: str) -> bool:
    """주민등록번호 유효성 검사 (날짜 + 체크섬)."""
    digits = re.sub(r'[-\s]', '', value)
    if len(digits) != 13:
        return False

    try:
        mm = int(digits[2:4])
        dd = int(digits[4:6])
        if not (1 <= mm <= 12 and 1 <= dd <= 31):
            return False
    except ValueError:
        return False

    gender_code = int(digits[6])
    if gender_code not in {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}:
        return False

    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    try:
        total = sum(int(d) * w for d, w in zip(digits[:12], weights))
        check = (11 - (total % 11)) % 10
        return check == int(digits[12])
    except (ValueError, IndexError):
        return False


def validate_luhn(value: str) -> bool:
    """Luhn 알고리즘으로 신용카드 번호 검증."""
    digits_str = re.sub(r'[\s\-]', '', value)
    if not digits_str.isdigit() or len(digits_str) < 13:
        return False

    digits = [int(d) for d in digits_str]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact_pii(value: str, pii_type: str) -> str:
    """PII 값을 보고서 표시용으로 마스킹합니다."""
    clean = value.strip()

    if pii_type == 'RRN':
        digits = re.sub(r'[-\s]', '', clean)
        if len(digits) == 13:
            return f"{digits[:2]}****-*******"
        return '*' * len(clean)

    elif pii_type == 'PHONE':
        digits = re.sub(r'[-\s]', '', clean)
        if len(digits) >= 10:
            return f"{digits[:3]}-****-{digits[-4:]}"
        return clean[:3] + '****'

    elif pii_type == 'CREDIT_CARD':
        digits = re.sub(r'[-\s]', '', clean)
        if len(digits) == 16:
            return f"{digits[:4]}-****-****-{digits[-4:]}"
        return digits[:4] + '-****-****-' + '****'

    elif pii_type == 'ACCOUNT_NO':
        if len(clean) >= 6:
            return clean[:3] + '*' * (len(clean) - 6) + clean[-3:]
        return '***'

    elif pii_type == 'EMAIL':
        parts = clean.split('@')
        if len(parts) == 2:
            local = parts[0]
            masked_local = local[:2] + '*' * (len(local) - 2) if len(local) > 2 else '**'
            return f"{masked_local}@{parts[1]}"
        return clean[:3] + '***'

    elif pii_type == 'NAME_IN_QUERY':
        if len(clean) >= 2:
            return clean[0] + '*' * (len(clean) - 1)
        return '*' * len(clean)

    elif pii_type == 'BIRTHDATE':
        if re.match(r'\d{4}', clean):
            return clean[:4] + '-**-**'
        return clean[:4] + '****'

    else:
        if len(clean) > 4:
            return clean[:2] + '*' * (len(clean) - 4) + clean[-2:]
        return '*' * len(clean)
