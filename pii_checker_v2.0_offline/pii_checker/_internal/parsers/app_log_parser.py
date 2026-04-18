"""애플리케이션 로그 파서 (Log4j, Python logging, Syslog 등)"""
from __future__ import annotations
import re
from parsers.base_parser import BaseParser
from models.log_event import LogEvent
from utils.date_utils import try_parse_timestamp

# Log4j: 2024-01-15 14:23:01,123 INFO  [threadName] ClassName - message
LOG4J_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d+)\s+'
    r'(DEBUG|INFO|WARN|ERROR|FATAL)\s+'
    r'(?:\[([^\]]+)\]\s+)?'   # optional thread name
    r'(\S+)\s+-\s+(.*)',
    re.IGNORECASE
)

# Python logging: 2024-01-15 14:23:01,123 - module - LEVEL - message
PYTHON_LOG_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d+)\s+-\s+(\S+)\s+-\s+(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+-\s+(.*)',
    re.IGNORECASE
)

# Syslog RFC3164: Jan 15 14:23:01 hostname process[pid]: message
SYSLOG_PATTERN = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)'
)

# 일반 타임스탬프 + 메시지
GENERIC_TS_PATTERN = re.compile(
    r'^(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2}[^\s]*)\s+(.*)'
)


class AppLogParser(BaseParser):
    log_type = 'app'

    def can_parse(self, sample_lines: list[str]) -> bool:
        count = sum(
            1 for line in sample_lines
            if LOG4J_PATTERN.match(line) or SYSLOG_PATTERN.match(line) or PYTHON_LOG_PATTERN.match(line)
        )
        return count / max(len(sample_lines), 1) > 0.2

    def parse_line(self, line: str, line_no: int, source_file: str, context: dict) -> LogEvent | None:
        if not line.strip() or line.startswith('#'):
            return None

        # Log4j 시도
        m = LOG4J_PATTERN.match(line)
        if m:
            ts = try_parse_timestamp(m.group(1))
            message = m.group(5)
            return self.make_event(
                raw_line=line,
                source_file=source_file,
                line_no=line_no,
                timestamp=ts,
                user_id=self.extract_user_id(message) or self.extract_user_id(line),
                ip_address=self.extract_ip(message),
                action=self.extract_action(message),
                query_text=message,
                extra={'level': m.group(2), 'logger': m.group(4)},
            )

        # Python logging 시도
        m = PYTHON_LOG_PATTERN.match(line)
        if m:
            ts = try_parse_timestamp(m.group(1))
            message = m.group(4)
            return self.make_event(
                raw_line=line,
                source_file=source_file,
                line_no=line_no,
                timestamp=ts,
                user_id=self.extract_user_id(message),
                ip_address=self.extract_ip(message),
                action=self.extract_action(message),
                query_text=message,
                extra={'level': m.group(3), 'module': m.group(2)},
            )

        # Syslog 시도
        m = SYSLOG_PATTERN.match(line)
        if m:
            ts = try_parse_timestamp(m.group(1))
            message = m.group(5)
            return self.make_event(
                raw_line=line,
                source_file=source_file,
                line_no=line_no,
                timestamp=ts,
                user_id=self.extract_user_id(message),
                ip_address=self.extract_ip(message),
                action=self.extract_action(message),
                target=m.group(2),  # hostname
                query_text=message,
                extra={'process': m.group(3), 'pid': m.group(4)},
            )

        # 일반 타임스탬프 패턴
        m = GENERIC_TS_PATTERN.match(line)
        if m:
            ts = try_parse_timestamp(m.group(1))
            message = m.group(2)
            return self.make_event(
                raw_line=line,
                source_file=source_file,
                line_no=line_no,
                timestamp=ts,
                user_id=self.extract_user_id(line),
                ip_address=self.extract_ip(line),
                action=self.extract_action(line),
                query_text=line,
            )

        # 폴백: 전체 라인 처리
        return self.make_event(
            raw_line=line,
            source_file=source_file,
            line_no=line_no,
            user_id=self.extract_user_id(line),
            query_text=line,
        )
