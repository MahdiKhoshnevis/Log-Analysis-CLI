import time
import argparse
from datetime import datetime
from urllib.parse import urlsplit
from read_log import parse_line, open_log_file, parse_filter_datetime, write_output

# Sensitive endpoints to monitor for automated access
SENSITIVE_PATHS = {"/login", "/api/checkout", "/admin"}

# Common keywords in automated/bot User-Agents (removed "http")
BOT_KEYWORDS = {"python-requests", "curl", "wget", "scrapy", "urllib", "libcurl"}

LIMIT = 15  # Max number of flagged suspicious IPs shown per indicator

def get_percentile(values, percentile=0.99):
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = min(int(len(sorted_vals) * percentile), len(sorted_vals) - 1)
    return float(sorted_vals[idx])

def is_bot_user_agent(ua: str) -> bool:
    if ua is None:
        return True  # Empty/missing UA is highly suspicious
    ua_lower = str(ua).lower()
    return any(keyword in ua_lower for keyword in BOT_KEYWORDS)

def is_sensitive_path(path: str) -> bool:
    if not path:
        return False
    clean_path = urlsplit(path).path
    return any(sensitive in clean_path for sensitive in SENSITIVE_PATHS)

def analyze_suspicious_behavior(log_file_path, start_time=None, end_time=None, format_opt="terminal"):
    start_time_perf = time.perf_counter()
    limit = LIMIT
    
    ip_stats = {}
    time_format = "%d/%b/%Y:%H:%M:%S %z"

    print(f"Reading logs and aggregating stats per IP from '{log_file_path}'...")
    try:
        with open_log_file(log_file_path) as file:
            for line in file:
                entry = parse_line(line)
                
                # Skip if IP is missing
                if entry.ip is None:
                    continue
                
                # Apply start/end datetime filters safely
                if start_time or end_time:
                    if entry.timestamp:
                        try:
                            dt = datetime.strptime(entry.timestamp, time_format)
                            if start_time and dt < start_time:
                                continue
                            if end_time and dt > end_time:
                                continue
                        except ValueError:
                            # Skip malformed timestamps when a time filter is active
                            continue
                    else:
                        # Skip missing timestamps when a time filter is active
                        continue
                
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
                
                if entry.status is not None:
                    status_str = str(entry.status)
                    # Check for Auth Failures (401, 403)
                    if status_str in {"401", "403"}:
                        stats["auth_failures"] += 1
                    
                    # Check for Not Found (404)
                    if status_str == "404":
                        stats["not_found"] += 1
                    
                    # Check for general client/server errors (4xx & 5xx)
                    if status_str.startswith(("4", "5")):
                        stats["errors"] += 1
                
                # Check for automated bot hits to sensitive paths
                if is_sensitive_path(entry.path) and is_bot_user_agent(entry.user_agent):
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
    error_rates = []
    bot_sensitives = []

    for ip, stats in ip_stats.items():
        totals.append(stats["total"])
        auth_failures.append(stats["auth_failures"])
        not_founds.append(stats["not_found"])
        
        rate = (stats["errors"] / stats["total"]) if stats["total"] > 0 else 0.0
        error_rates.append(rate)
        
        bot_sensitives.append(stats["bot_sensitive"])

    # Determine 99th percentile threshold for each metric
    threshold_total = get_percentile(totals, 0.99)
    threshold_auth = get_percentile(auth_failures, 0.99)
    threshold_not_found = get_percentile(not_founds, 0.99)
    threshold_error_rate = get_percentile(error_rates, 0.99)
    threshold_bot_sensitive = get_percentile(bot_sensitives, 0.99)

    elapsed_time = time.perf_counter() - start_time_perf

    json_data = {
        "execution_time_sec": round(elapsed_time, 4),
        "thresholds": {
            "total_requests": threshold_total,
            "auth_failures": threshold_auth,
            "not_found_hits": threshold_not_found,
            "error_rate_pct": threshold_error_rate * 100,
            "bot_sensitive_hits": threshold_bot_sensitive
        },
        "indicators": {}
    }

    # Helper function to generate stats for an indicator
    def process_indicator(title, metric_key, threshold, json_key, suffix="", is_ratio=False):
        if is_ratio:
            header = f"{title} (99th Percentile Threshold: {threshold * 100:.2f}%)"
        else:
            header = f"{title} (99th Percentile Threshold: {int(threshold):,}{suffix})"

        flagged = []
        for ip, stats in ip_stats.items():
            if is_ratio and stats["total"] < 5:
                continue
            if is_ratio:
                val = (stats["errors"] / stats["total"]) if stats["total"] > 0 else 0.0
            else:
                val = stats[metric_key]
            if val >= threshold and val > 0:
                flagged.append((ip, val, stats["total"]))
        flagged.sort(key=lambda x: x[1], reverse=True)

        json_flagged_list = []
        for ip, val, total_req in flagged[:limit]:
            json_flagged_list.append({
                "ip": ip,
                "value": val * 100 if is_ratio else val,
                "total_requests": total_req
            })
        json_data["indicators"][json_key] = json_flagged_list

        if not flagged:
            rows = "No suspicious IPs detected for this indicator.\n"
        else:
            rows = (
                f"{'Suspicious IP':<20} | {'Metric Value':<18} | {'Total Requests':<15}\n"
                + "-"*50 + "\n"
                + "".join(
                    f"{ip:<20} | {f'{val * 100:.2f}%' if is_ratio else f'{int(val):,}{suffix}':<18} | {total_req:<15,}\n"
                    for ip, val, total_req in flagged[:limit]
                )
            )

        return (
            "="*50 + "\n"
            + header + "\n"
            + "="*50 + "\n"
            + rows
            + "\n"
        )

    # 1. Total Requests Volume Outliers
    r1 = process_indicator("1. High Request Volume (DoS/Scraping)", "total", threshold_total, "request_volume", " reqs")

    # 2. Auth Failures Outliers
    r2 = process_indicator("2. High Authentication/Authorization Failures", "auth_failures", threshold_auth, "auth_failures", " failures")

    # 3. Not Found Outliers
    r3 = process_indicator("3. High Directory Scanning (404 Fuzzing)", "not_found", threshold_not_found, "directory_scanning", " hits")

    # 4. Error Ratio Outliers
    r4 = process_indicator("4. High Error Ratio (Client/Server Errors)", None, threshold_error_rate, "error_rate_pct", is_ratio=True)

    # 5. Bot hits on sensitive endpoints
    r5 = process_indicator("5. Automated Bot Activity on Sensitive Paths", "bot_sensitive", threshold_bot_sensitive, "bot_sensitive", " hits")

    text_report = (
        "\n" + "="*50 + "\n"
        "           SUSPICIOUS BEHAVIOR ANALYSIS REPORT (99th Percentile)\n"
        + f"           Execution Time: {elapsed_time:.4f} seconds\n"
        + "="*50 + "\n"
        + r1 + r2 + r3 + r4 + r5
    )
    write_output(text_report, json_data, format_opt, "detect_suspicious")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze access logs to identify suspicious client behavior.")
    parser.add_argument("log_path", type=str, help="Path to the access log file")
    parser.add_argument("--start", type=parse_filter_datetime, help="Start datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_filter_datetime, help="End datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--format", type=str, choices=["terminal", "txt", "json"], default="terminal",
                        help="Output format (default: terminal)")
    args = parser.parse_args()

    analyze_suspicious_behavior(args.log_path, start_time=args.start, end_time=args.end, format_opt=args.format)
