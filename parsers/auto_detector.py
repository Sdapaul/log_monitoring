"""로그 형식 자동 감지"""
from __future__ import annotations
from config import COMPILED_FORMAT_SIGNATURES
from parsers.web_access_parser import WebAccessParser
from parsers.app_log_parser import AppLogParser
from parsers.db_access_parser import DbAccessParser
from parsers.generic_parser import GenericParser

# 파서 우선순위 순서
ALL_PARSERS = [
    DbAccessParser(),
    WebAccessParser(),
    AppLogParser(),
    GenericParser(),
]


def detect_format(file_path: str, sample_size: int = 100) -> tuple[str, object]:
    """
    파일의 처음 N줄을 읽어 최적 파서를 반환합니다.
    구체적인 형식이 일반 형식보다 우선합니다.
    Returns: (format_name, parser_instance)
    """
    from pipeline.stream_reader import stream_lines

    sample_lines = []
    for line_no, line in stream_lines(file_path, show_progress=False):
        if line.strip():
            sample_lines.append(line)
        if len(sample_lines) >= sample_size:
            break

    if not sample_lines:
        return 'unknown', GenericParser()

    # 형식별 특이성 점수 (높을수록 더 구체적인 형식)
    SPECIFICITY = {
        'oracle_audit': 10,
        'mysql_general': 9,
        'mssql_audit': 9,
        'apache_combined': 8,
        'log4j_standard': 7,
        'syslog_rfc5424': 4,
        'syslog_rfc3164': 4,
        'csv_generic': 2,
    }

    scores: dict[str, float] = {}
    for fmt_name, fmt_info in COMPILED_FORMAT_SIGNATURES.items():
        pattern = fmt_info['compiled']
        match_count = sum(1 for line in sample_lines if pattern.search(line))
        if match_count > 0:
            # 매치 비율 * 특이성 가중치로 최종 점수 산정
            ratio = match_count / len(sample_lines)
            specificity = SPECIFICITY.get(fmt_name, 5)
            scores[fmt_name] = ratio * specificity

    if scores:
        best_fmt = max(scores, key=lambda k: scores[k])
        # 원래 매치 수로 신뢰도 계산
        orig_pattern = COMPILED_FORMAT_SIGNATURES[best_fmt]['compiled']
        match_count = sum(1 for line in sample_lines if orig_pattern.search(line))
        confidence = match_count / len(sample_lines) * 100
        print(f"  [형식감지] {best_fmt} (신뢰도: {confidence:.0f}%)")

        # 형식에 맞는 파서 선택
        if 'oracle' in best_fmt or 'mysql' in best_fmt or 'mssql' in best_fmt:
            return best_fmt, DbAccessParser()
        elif 'apache' in best_fmt:
            return best_fmt, WebAccessParser()
        elif 'log4j' in best_fmt or 'syslog' in best_fmt:
            return best_fmt, AppLogParser()
    else:
        print(f"  [형식감지] 알 수 없는 형식 - 범용 파서 사용")

    return 'generic', GenericParser()
