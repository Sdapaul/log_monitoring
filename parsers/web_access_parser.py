"""Apache/Nginx Combined Log Format 파서"""
from __future__ import annotations
import re
from datetime import datetime
from parsers.base_parser import BaseParser
from models.log_event import LogEvent
from utils.date_utils import try_parse_timestamp

# Apache Combined: 192.168.1.1 - user [15/Jan/2024:14:23:01 +0900] "GET /path HTTP/1.1" 200 1234 "referer" "useragent"
APACHE_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+'          # IP, ident, user
    r'\[([^\]]+)\]\s+'                    # [timestamp]
    r'"(\w+)\s+([^\s"]+)[^"]*"\s+'        # "METHOD /path HTTP/1.x"
    r'(\d{3})\s+(\S+)'                    # status code, bytes
)

# URL에서 파라미터 추출
QUERY_PARAM_PATTERN = re.compile(r'\?(.+)$')


class WebAccessParser(BaseParser):
    log_type = 'web'

    def can_parse(self, sample_lines: list[str]) -> bool:
        count = sum(1 for line in sample_lines if APACHE_PATTERN.match(line))
        return count / max(len(sample_lines), 1) > 0.3

    def parse_line(self, line: str, line_no: int, source_file: str, context: dict) -> LogEvent | None:
        if not line.strip():
            return None

        m = APACHE_PATTERN.match(line)
        if not m:
            # Apache 형식이 아니면 범용으로 처리
            return self.make_event(line, source_file, line_no, query_text=line)

        ip = m.group(1)
        user_id = m.group(2) if m.group(2) != '-' else None
        ts_str = m.group(3)
        method = m.group(4)
        path = m.group(5)
        status = m.group(6)

        # 타임스탬프 파싱
        ts = try_parse_timestamp(ts_str)

        # URL 파라미터 (PII가 포함될 수 있음)
        query_params = ''
        param_m = QUERY_PARAM_PATTERN.search(path)
        if param_m:
            query_params = param_m.group(1)

        # 사용자 ID가 없으면 User-Agent 또는 전체 라인에서 추출 시도
        if not user_id:
            user_id = self.extract_user_id(line)

        return self.make_event(
            raw_line=line,
            source_file=source_file,
            line_no=line_no,
            timestamp=ts,
            user_id=user_id,
            ip_address=ip,
            action=method,
            target=path.split('?')[0],
            query_text=f"{method} {path} {query_params}",
            extra={'status_code': status, 'url_path': path},
        )
