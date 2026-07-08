import os
import re
import time
import argparse
from datetime import datetime
from read_log import parse_line, LogEntry, open_log_file, parse_filter_datetime, write_output

# Sensitive endpoints to monitor for automated access
SENSITIVE_PATHS = {"/login", "/api/checkout", "/admin"}

# Common keywords in automated/bot User-Agents
BOT_KEYWORDS = {"python-requests", "curl", "wget", "http", "scrapy", "urllib", "libcurl"}

def get_percentile(values, percentile=0.99):
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = min(int(len(sorted_vals) * percentile), len(sorted_vals) - 1)
    return float(sorted_vals[idx])

def is_bot_user_agent(ua: str) -> bool:
    if ua == "EMPTY_USER_AGENT":
        return True  # Empty/missing UA is highly suspicious
    ua_lower = ua.lower()
    return any(keyword in ua_lower for keyword in BOT_KEYWORDS)

def analyze_suspicious_behavior(log_file_path, limit=15, start_time=None, end_time=None, format_opt="terminal"):
    start_time_perf = time.perf_counter()
    
    ip_stats = {}
    time_format = "%d/%b/%Y:%H:%M:%S %z"

    print(f"Reading logs and aggregating stats per IP from '{log_file_path}'...")
    try:
        with open_log_file(log_file_path) as file:
            for line in file:
                entry = parse_line(line)
                if entry.ip == "EMPTY_IP":
                    continue
                
                # Apply start/end datetime filters
                if entry.timestamp != "EMPTY_TIME" and (start_time or end_time):
                    try:
                        dt = datetime.strptime(entry.timestamp, time_format)
                        if start_time and dt < start_time:
                            continue
                        if end_time and dt > end_time:
                            continue
                    except Exception:
                        pass
                
                if entry.ip not in ip_stats:
                    ip_stats[entry.ip] = {
                        "total": 0,
                        "auth_failures": 0,
                        "not_found": 0,
                        "errors": 0,
                        "bot_sensitive": 0
                    }
                
                stats = ip_stats[entry.ip]
                stats["total"] += 1
                
                # Check for Auth Failures (401, 403)
                if entry.status in {"401", "403"}:
                    stats["auth_failures"] += 1
                
                # Check for Not Found (404)
                if entry.status == "404":
                    stats["not_found"] += 1
                
                # Check for general client/server errors (4xx & 5xx)
                if entry.status != "EMPTY_STATUS" and entry.status.startswith(("4", "5")):
                    stats["errors"] += 1
                
                # Check for automated bot hits to sensitive paths
                if entry.path in SENSITIVE_PATHS and is_bot_user_agent(entry.user_agent):
                    stats["bot_sensitive"] += 1

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return

    if not ip_stats:
        print("No traffic data found matching the filter criteria.")
        return

    # Calculate metrics lists across all active IPs
    totals = []
    auth_failures = []
    not_founds = []
    error_ratios = []
    bot_sensitives = []

    for ip, stats in ip_stats.items():
        totals.append(stats["total"])
        auth_failures.append(stats["auth_failures"])
        not_founds.append(stats["not_found"])
        
        ratio = (stats["errors"] / stats["total"]) if stats["total"] > 0 else 0.0
        error_ratios.append(ratio)
        
        bot_sensitives.append(stats["bot_sensitive"])

    # Determine 99th percentile threshold for each metric
    threshold_total = get_percentile(totals, 0.99)
    threshold_auth = get_percentile(auth_failures, 0.99)
    threshold_not_found = get_percentile(not_founds, 0.99)
    threshold_error_ratio = get_percentile(error_ratios, 0.99)
    threshold_bot_sensitive = get_percentile(bot_sensitives, 0.99)

    elapsed_time = time.perf_counter() - start_time_perf

    report_lines = []
    report_lines.append("\n" + "#" * 65)
    report_lines.append("           SUSPICIOUS BEHAVIOR ANALYSIS REPORT (99th Percentile)")
    report_lines.append(f"           Execution Time: {elapsed_time:.4f} seconds")
    report_lines.append("#" * 65 + "\n")

    json_data = {
        "execution_time_sec": round(elapsed_time, 4),
        "thresholds": {
            "total_requests": threshold_total,
            "auth_failures": threshold_auth,
            "not_found_hits": threshold_not_found,
            "error_ratio_pct": threshold_error_ratio * 100,
            "bot_sensitive_hits": threshold_bot_sensitive
        },
        "indicators": {}
    }

    # Helper function to generate stats for an indicator
    def process_indicator(title, metric_key, threshold, json_key, suffix="", is_ratio=False):
        report_lines.append("=" * 65)
        if is_ratio:
            report_lines.append(f"{title} (99th Percentile Threshold: {threshold * 100:.2f}%)")
        else:
            report_lines.append(f"{title} (99th Percentile Threshold: {int(threshold):,}{suffix})")
        report_lines.append("=" * 65)
        
        flagged = []
        for ip, stats in ip_stats.items():
            if is_ratio:
                val = (stats["errors"] / stats["total"]) if stats["total"] > 0 else 0.0
            else:
                val = stats[metric_key]
                
            if val > threshold and val > 0:
                flagged.append((ip, val, stats["total"]))
                
        flagged.sort(key=lambda x: x[1], reverse=True)
        
        json_flagged_list = []
        for ip, val, total_req in flagged:
            json_flagged_list.append({
                "ip": ip,
                "value": val * 100 if is_ratio else val,
                "total_requests": total_req
            })
        json_data["indicators"][json_key] = json_flagged_list
        
        if not flagged:
            report_lines.append("No suspicious IPs detected for this indicator.")
        else:
            report_lines.append(f"{'Suspicious IP':<20} | {'Metric Value':<18} | {'Total Requests':<15}")
            report_lines.append("-" * 65)
            for ip, val, total_req in flagged[:limit]:
                if is_ratio:
                    val_str = f"{val * 100:.2f}%"
                else:
                    val_str = f"{int(val):,}{suffix}"
                report_lines.append(f"{ip:<20} | {val_str:<18} | {total_req:<15,}")
        report_lines.append("\n")

    # 1. Total Requests Volume Outliers
    process_indicator("1. High Request Volume (DoS/Scraping)", "total", threshold_total, "request_volume", " reqs")
    
    # 2. Auth Failures Outliers
    process_indicator("2. High Authentication Failures (Brute-Force)", "auth_failures", threshold_auth, "auth_failures", " failures")
    
    # 3. Not Found Outliers
    process_indicator("3. High Directory Scanning (404 Fuzzing)", "not_found", threshold_not_found, "directory_scanning", " hits")
    
    # 4. Error Ratio Outliers
    process_indicator("4. High Error Ratio (Client/Server Errors)", None, threshold_error_ratio, "error_ratio", is_ratio=True)
    
    # 5. Bot hits on sensitive endpoints
    process_indicator("5. Automated Bot Activity on Sensitive Paths", "bot_sensitive", threshold_bot_sensitive, "bot_sensitive", " hits")

    text_report = "\n".join(report_lines)
    write_output(text_report, json_data, format_opt, "detect_suspicious")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze access logs to identify suspicious client behavior.")
    parser.add_argument("log_path", type=str, help="Path to the access log file")
    parser.add_argument("--top-n", type=int, default=15, help="Limit number of flagged suspicious IPs shown (default: 15)")
    parser.add_argument("--start", type=parse_filter_datetime, help="Start datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_filter_datetime, help="End datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--format", type=str, choices=["terminal", "txt", "json"], default="terminal",
                        help="Output format (default: terminal)")
    args = parser.parse_args()
    
    analyze_suspicious_behavior(args.log_path, limit=args.top_n, start_time=args.start, end_time=args.end, format_opt=args.format)
