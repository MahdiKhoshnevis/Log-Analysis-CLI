import os
import re
import gzip

class LogEntry:
    def __init__(self, ip="EMPTY_IP", timestamp="EMPTY_TIME", method="EMPTY_METHOD",
                 path="EMPTY_PATH", protocol="EMPTY_PROTOCOL", status="EMPTY_STATUS",
                 size="EMPTY_SIZE", referer="EMPTY_REFERER", user_agent="EMPTY_USER_AGENT"):
        self.ip = ip
        self.timestamp = timestamp
        self.method = method
        self.path = path
        self.protocol = protocol
        self.status = status
        self.size = size
        self.referer = referer
        self.user_agent = user_agent

    def __repr__(self):
        return (f"LogEntry(\n"
                f"  ip={self.ip!r},\n"
                f"  timestamp={self.timestamp!r},\n"
                f"  method={self.method!r},\n"
                f"  path={self.path!r},\n"
                f"  protocol={self.protocol!r},\n"
                f"  status={self.status!r},\n"
                f"  size={self.size!r},\n"
                f"  referer={self.referer!r},\n"
                f"  user_agent={self.user_agent!r}\n"
                f")")

# Regular expression to extract standard parts of Combined Log Format.
# Group 1: IP (non-whitespace)
# Group 2: Timestamp (inside [])
# Group 3: Request line (inside "")
# Group 4: Status code (non-whitespace)
# Group 5: Size (non-whitespace)
# Group 6: Referer (inside "")
# Group 7: User agent (inside "")
LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(.*?)"\s+(\S+)\s+(\S+)\s+"(.*?)"\s+"(.*?)"$'
)

def parse_line(line: str) -> LogEntry:
    line = line.strip()
    if not line:
        return LogEntry()

    match = LOG_PATTERN.match(line)
    if not match:
        # Return fallback/empty entry if the line format is completely unexpected
        return LogEntry()

    # Extract raw fields from regex groups
    raw_ip = match.group(1)
    raw_timestamp = match.group(2)
    raw_request = match.group(3)
    raw_status = match.group(4)
    raw_size = match.group(5)
    raw_referer = match.group(6)
    raw_user_agent = match.group(7)

    # Helper function to assign filler values if field is empty or "-"
    def clean(val, filler):
        if not val or val == "-":
            return filler
        return val

    # Parse request details (e.g. "GET /products HTTP/1.1")
    method = "EMPTY_METHOD"
    path = "EMPTY_PATH"
    protocol = "EMPTY_PROTOCOL"

    if raw_request and raw_request != "-":
        parts = raw_request.split()
        if len(parts) >= 1:
            method = parts[0]
        if len(parts) >= 2:
            path = parts[1]
        if len(parts) >= 3:
            protocol = parts[2]

    # Validate status code (must be 3 digits and within standard HTTP range 100-599)
    status = clean(raw_status, "EMPTY_STATUS")
    if status != "EMPTY_STATUS":
        if not (status.isdigit() and len(status) == 3 and 100 <= int(status) <= 599):
            status = "EMPTY_STATUS"

    return LogEntry(
        ip=clean(raw_ip, "EMPTY_IP"),
        timestamp=clean(raw_timestamp, "EMPTY_TIME"),
        method=clean(method, "EMPTY_METHOD"),
        path=clean(path, "EMPTY_PATH"),
        protocol=clean(protocol, "EMPTY_PROTOCOL"),
        status=status,
        size=clean(raw_size, "EMPTY_SIZE"),
        referer=clean(raw_referer, "EMPTY_REFERER"),
        user_agent=clean(raw_user_agent, "EMPTY_USER_AGENT")
    )

def open_log_file(file_path):
    """
    Opens a file, transparently handling gzip compressed (.gz) logs as text.
    """
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    return open(file_path, "r", encoding="utf-8", errors="replace")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Read access logs line-by-line and show parsing example.")
    parser.add_argument("log_path", type=str, help="Path to the access log file (absolute or relative)")
    args = parser.parse_args()
    
    log_file_path = args.log_path
    
    print(f"Testing parser on the first 5 lines of the log file at '{log_file_path}':\n")
    try:
        with open_log_file(log_file_path) as file:
            for idx, line in enumerate(file, 1):
                entry = parse_line(line)
                print(f"--- Line {idx} ---")
                print(entry)
                if idx >= 5:
                    break
    except FileNotFoundError:
        print(f"Error: The log file at {log_file_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

