"""범용 폴백 파서 - 알 수 없는 형식의 로그를 처리합니다."""
from __future__ import annotations
from parsers.base_parser import BaseParser
from models.log_event import LogEvent
from utils.date_utils import try_parse_timestamp


class GenericParser(BaseParser):
    log_type = 'unknown'

    def can_parse(self, sample_lines: list[str]) -> bool:
        return True  # 항상 처리 가능

    def parse_line(self, line: str, line_no: int, source_file: str, context: dict) -> LogEvent | None:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            return None

        ts = try_parse_timestamp(stripped)
        user_id = self.extract_user_id(stripped)
        ip = self.extract_ip(stripped)
        action = self.extract_action(stripped)

        return self.make_event(
            raw_line=line,
            source_file=source_file,
            line_no=line_no,
            timestamp=ts,
            user_id=user_id,
            ip_address=ip,
            action=action,
            query_text=stripped,
        )
