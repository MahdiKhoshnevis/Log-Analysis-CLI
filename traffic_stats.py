import os
import time
from datetime import datetime
from read_log import parse_line, open_log_file, parse_filter_datetime, write_output

def calculate_stats(log_file_path, top_n=10, start_time=None, end_time=None, format_opt="terminal"):
    start_time_perf = time.perf_counter()
    
    total_requests = 0
    unique_ips = set()
    path_counts = {}
    error_requests = 0
    
    # Time format in the log: "01/Jun/2026:00:00:00 +0000"
    time_format = "%d/%b/%Y:%H:%M:%S %z"
    
    print(f"Reading and aggregating log stats line-by-line from '{log_file_path}'...")
    try:
        with open_log_file(log_file_path) as file:
            for line in file:
                entry = parse_line(line)
                
                # Skip completely empty lines
                if entry.ip == "EMPTY_IP" and entry.timestamp == "EMPTY_TIME":
                    continue
                
                # Apply start/end filters
                if entry.timestamp != "EMPTY_TIME" and (start_time or end_time):
                    try:
                        dt = datetime.strptime(entry.timestamp, time_format)
                        if start_time and dt < start_time:
                            continue
                        if end_time and dt > end_time:
                            continue
                    except Exception:
                        pass
                
                total_requests += 1
                
                # Track unique IPs
                if entry.ip != "EMPTY_IP":
                    unique_ips.add(entry.ip)
                
                # Track endpoint/path counts
                if entry.path != "EMPTY_PATH":
                    path_counts[entry.path] = path_counts.get(entry.path, 0) + 1
                    
                # Track 4xx and 5xx errors
                if entry.status != "EMPTY_STATUS":
                    if entry.status.startswith(("4", "5")):
                        error_requests += 1

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return

    if total_requests == 0:
        print("No requests found matching the filter criteria.")
        return

    total_unique_ips = len(unique_ips)
    
    # Sort paths by count descending to find top N
    top_endpoints = sorted(path_counts.items(), key=lambda item: item[1], reverse=True)[:top_n]
    
    # Calculate error rate percentage
    error_rate = (error_requests / total_requests) * 100

    elapsed_time = time.perf_counter() - start_time_perf

    # Build report text content
    output_lines = []
    output_lines.append("\n" + "="*50)
    output_lines.append("                 LOG ANALYSIS REPORT")
    output_lines.append("="*50)
    output_lines.append(f"Total Requests:           {total_requests:,}")
    output_lines.append(f"Unique Client IPs:        {total_unique_ips:,}")
    output_lines.append(f"Error Rate (4xx & 5xx):   {error_rate:.2f}% ({error_requests:,} requests)")
    output_lines.append(f"Execution Time:           {elapsed_time:.4f} seconds")
    output_lines.append("="*50)
    output_lines.append(f"Top {top_n} Most Frequent Endpoints:")
    output_lines.append("-"*50)
    for rank, (path, count) in enumerate(top_endpoints, 1):
        output_lines.append(f"{rank:2d}. {path:<30} | {count:<10,} requests")
    output_lines.append("="*50 + "\n")
    text_report = "\n".join(output_lines)
    
    # Build JSON structure
    json_data = {
        "total_requests": total_requests,
        "unique_ips": total_unique_ips,
        "error_requests": error_requests,
        "error_rate_pct": error_rate,
        "execution_time_sec": round(elapsed_time, 4),
        "top_endpoints": [
            {"path": path, "count": count} for path, count in top_endpoints
        ]
    }
    
    # Output result
    write_output(text_report, json_data, format_opt, "traffic_stats")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Calculate metrics and statistics from access logs.")
    parser.add_argument("log_path", type=str, help="Path to the access log file (absolute or relative)")
    parser.add_argument("--top-n", type=int, default=10, help="Number of top frequent endpoints to show (default: 10)")
    parser.add_argument("--start", type=parse_filter_datetime, help="Start datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_filter_datetime, help="End datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--format", type=str, choices=["terminal", "txt", "json"], default="terminal",
                        help="Output format (default: terminal)")
    args = parser.parse_args()
    
    calculate_stats(args.log_path, top_n=args.top_n, start_time=args.start, end_time=args.end, format_opt=args.format)
