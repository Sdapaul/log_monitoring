"""
대용량 로그 파일을 청크 단위로 스트리밍 읽기.
UTF-8, EUC-KR, CP949 인코딩 자동 감지 지원.
gzip 파일 지원. Word/PDF/Excel 문서 지원.
"""
from __future__ import annotations
import gzip
import os
from pathlib import Path
from typing import Iterator


ENCODINGS_TO_TRY = ['utf-8', 'utf-8-sig', 'euc-kr', 'cp949', 'latin-1']
CHUNK_SIZE = 50_000  # 청크당 최대 라인 수


def detect_encoding(file_path: str | Path) -> str:
    """파일 처음 4KB를 읽어 인코딩을 감지합니다."""
    path = Path(file_path)
    opener = gzip.open if path.suffix == '.gz' else open

    for encoding in ENCODINGS_TO_TRY:
        try:
            with opener(path, 'rt', encoding=encoding) as f:
                f.read(4096)
            return encoding
        except (UnicodeDecodeError, Exception):
            continue
    return 'utf-8'  # 최후 fallback


def stream_lines(
    file_path: str | Path,
    chunk_size: int = CHUNK_SIZE,
    show_progress: bool = True,
) -> Iterator[tuple[int, str]]:
    """
    파일을 한 줄씩 스트리밍합니다.
    Word/PDF/Excel 문서는 텍스트 추출 후 라인 단위로 yield합니다.
    Yields: (line_no, line_text)
    """
    path = Path(file_path)
    file_size = os.path.getsize(path)

    # 문서 파일 (Word/PDF/Excel)
    from pipeline.doc_extractor import is_document, extract_lines
    if is_document(path):
        if show_progress:
            print(f"  [문서읽기] {path.name} ({file_size / 1024 / 1024:.1f} MB)")
        yield from extract_lines(path)
        return

    encoding = detect_encoding(path)
    opener = gzip.open if path.suffix == '.gz' else open

    if show_progress:
        print(f"  [읽기] {path.name} ({file_size / 1024 / 1024:.1f} MB, 인코딩: {encoding})")

    try:
        with opener(path, 'rt', encoding=encoding, errors='replace') as f:
            for line_no, line in enumerate(f, start=1):
                yield line_no, line.rstrip('\n\r')
    except Exception as e:
        print(f"  [오류] 파일 읽기 실패 {path.name}: {e}")


def stream_multiline_records(
    file_path: str | Path,
    record_start_pattern,  # re.Pattern
    chunk_size: int = CHUNK_SIZE,
) -> Iterator[tuple[int, str]]:
    """
    멀티라인 레코드(예: Oracle Audit)를 하나의 레코드로 묶어 스트리밍합니다.
    record_start_pattern: 새 레코드 시작을 나타내는 컴파일된 정규식
    Yields: (start_line_no, full_record_text)
    """
    buffer_lines = []
    start_line_no = 1
    current_line_no = 0

    for line_no, line in stream_lines(file_path):
        current_line_no = line_no
        if record_start_pattern.search(line) and buffer_lines:
            # 이전 레코드 플러시
            yield start_line_no, '\n'.join(buffer_lines)
            buffer_lines = []
            start_line_no = line_no
        buffer_lines.append(line)

    # 마지막 레코드
    if buffer_lines:
        yield start_line_no, '\n'.join(buffer_lines)
