import re
import gzip
import json
import http
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

VALID_STATUS_CODES = {status.value for status in http.HTTPStatus}

# Regular expression to extract standard parts of Combined Log Format.
LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(.*?)"\s+(\S+)\s+(\S+)\s+"(.*?)"\s+"(.*?)"$'
)


@dataclass
class LogEntry:
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    protocol: Optional[str] = None
    status: Optional[int] = None
    size: Optional[int] = None
    referer: Optional[str] = None
    user_agent: Optional[str] = None


def parse_line(line: str) -> LogEntry:
    line = line.strip()
    if not line:
        return LogEntry()

    match = LOG_PATTERN.match(line)
    if not match:
        return LogEntry()

    raw_ip = match.group(1)
    raw_timestamp = match.group(2)
    raw_request = match.group(3)
    raw_status = match.group(4)
    raw_size = match.group(5)
    raw_referer = match.group(6)
    raw_user_agent = match.group(7)

    def clean(val: str) -> Optional[str]:
        return val if val and val != "-" else None

    method = None
    path = None
    protocol = None

    if raw_request and raw_request != "-":
        parts = raw_request.split()
        if len(parts) == 3:
            method, path, protocol = parts
        elif len(parts) > 0:
            method = parts[0]
            if len(parts) > 1:
                path = parts[1]
            if len(parts) > 2:
                protocol = parts[2]

    status = None
    raw_status_clean = clean(raw_status)
    if raw_status_clean and raw_status_clean.isdigit():
        status_val = int(raw_status_clean)
        if status_val in VALID_STATUS_CODES or status_val == 499:
            status = status_val

    size = None
    raw_size_clean = clean(raw_size)
    if raw_size_clean and raw_size_clean.isdigit():
        size = int(raw_size_clean)

    return LogEntry(
        ip=clean(raw_ip),
        timestamp=clean(raw_timestamp),
        method=clean(method),
        path=clean(path),
        protocol=clean(protocol),
        status=status,
        size=size,
        referer=clean(raw_referer),
        user_agent=clean(raw_user_agent)
    )


def open_log_file(file_path: str):
    """
    Opens a file, transparently handling gzip compressed (.gz) logs as text.
    """
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    return open(file_path, "r", encoding="utf-8", errors="replace")


def _parse_dt(dt_str: str) -> Tuple[Optional[datetime], Optional[str]]:
    if not dt_str:
        return None, None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(dt_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt, fmt
        except ValueError:
            continue
    raise ValueError(f"Invalid datetime format: '{dt_str}'. Use YYYY-MM-DD HH:MM:SS.")


def parse_filter_datetime(dt_str: str) -> Optional[datetime]:
    """
    Parses start filtering datetime. Naive datetimes are treated as UTC.
    """
    dt, _ = _parse_dt(dt_str)
    return dt


def parse_end_datetime(dt_str: str) -> Optional[datetime]:
    """
    Parses end filtering datetime. If date-only format is provided, returns the end of that day.
    """
    dt, fmt = _parse_dt(dt_str)
    if dt and fmt == "%Y-%m-%d":
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt


def write_output(text_content: str, json_data: dict, format_opt: str, default_filename: str):
    """
    Outputs data to terminal, text file, or JSON file.
    """
    if format_opt == "terminal":
        print(text_content)
    elif format_opt == "txt":
        filename = default_filename + ".txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(text_content)
        print(f"Report successfully saved to text file: {filename}")
    elif format_opt == "json":
        filename = default_filename + ".json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=4, default=str)
        print(f"Data successfully saved to JSON file: {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read access logs line-by-line and show parsing example.")
    parser.add_argument("log_path", type=str, help="Path to the access log file (absolute or relative)")
    parser.add_argument("--start", type=parse_filter_datetime, help="Start datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_end_datetime, help="End datetime filter (YYYY-MM-DD HH:MM:SS)")
    args = parser.parse_args()
    
    log_file_path = args.log_path
    time_format = "%d/%b/%Y:%H:%M:%S %z"
    
    print(f"Testing parser on the log file at '{log_file_path}':\n")
    
    total_lines = 0
    parsed_lines = 0
    invalid_lines = 0
    skipped_lines = 0

    try:
        with open_log_file(log_file_path) as file:
            printed_count = 0
            for idx, line in enumerate(file, 1):
                total_lines += 1
                entry = parse_line(line)
                
                if entry.ip is None:
                    invalid_lines += 1
                    continue
                else:
                    parsed_lines += 1

                if entry.timestamp is not None and (args.start or args.end):
                    try:
                        dt = datetime.strptime(entry.timestamp, time_format)
                        if args.start and dt < args.start:
                            skipped_lines += 1
                            continue
                        if args.end and dt > args.end:
                            skipped_lines += 1
                            continue
                    except ValueError:
                        pass
                
                if printed_count < 5:
                    print(f"--- Matching Line {idx} ---")
                    print(entry)
                    printed_count += 1

            print("\n--- Summary ---")
            print(f"Total lines: {total_lines}")
            print(f"Successfully parsed: {parsed_lines}")
            print(f"Invalid lines: {invalid_lines}")
            print(f"Skipped (time filter): {skipped_lines}")

    except FileNotFoundError:
        print(f"Error: The log file at {log_file_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
