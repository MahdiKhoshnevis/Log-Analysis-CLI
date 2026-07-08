import os
import re
import argparse
from read_log import parse_line, LogEntry, open_log_file

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

def analyze_suspicious_behavior(log_file_path):
    # Dictionary structure per IP:
    # {
    #   ip: {
    #     'total': int,
    #     'auth_failures': int,  # 401, 403
    #     'not_found': int,      # 404
    #     'errors': int,         # 4xx, 5xx
    #     'bot_sensitive': int   # bots hitting sensitive paths
    #   }
    # }
    ip_stats = {}

    print(f"Reading logs and aggregating stats per IP from '{log_file_path}'...")
    try:
        with open_log_file(log_file_path) as file:
            for line in file:
                entry = parse_line(line)
                if entry.ip == "EMPTY_IP":
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
        print("No traffic data found.")
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
        
        # Error ratio: total errors / total requests
        ratio = (stats["errors"] / stats["total"]) if stats["total"] > 0 else 0.0
        error_ratios.append(ratio)
        
        bot_sensitives.append(stats["bot_sensitive"])

    # Determine 99th percentile threshold for each metric
    threshold_total = get_percentile(totals, 0.99)
    threshold_auth = get_percentile(auth_failures, 0.99)
    threshold_not_found = get_percentile(not_founds, 0.99)
    threshold_error_ratio = get_percentile(error_ratios, 0.99)
    threshold_bot_sensitive = get_percentile(bot_sensitives, 0.99)

    # Helper function to print reports for each indicator
    def report_indicator(title, metric_key, threshold, suffix="", is_ratio=False):
        print("=" * 65)
        if is_ratio:
            print(f"{title} (99th Percentile Threshold: {threshold * 100:.2f}%)")
        else:
            print(f"{title} (99th Percentile Threshold: {int(threshold):,}{suffix})")
        print("=" * 65)
        
        flagged = []
        for ip, stats in ip_stats.items():
            if is_ratio:
                val = (stats["errors"] / stats["total"]) if stats["total"] > 0 else 0.0
            else:
                val = stats[metric_key]
                
            # We flag if it is strictly greater than the threshold,
            # and greater than zero (to avoid flagging zero counts if threshold is 0)
            if val > threshold and val > 0:
                flagged.append((ip, val, stats["total"]))
                
        # Sort flagged IPs by the violation value in descending order
        flagged.sort(key=lambda x: x[1], reverse=True)
        
        if not flagged:
            print("No suspicious IPs detected for this indicator.")
        else:
            print(f"{'Suspicious IP':<20} | {'Metric Value':<18} | {'Total Requests':<15}")
            print("-" * 65)
            for ip, val, total_req in flagged[:15]:  # Limit display to top 15 violations
                if is_ratio:
                    val_str = f"{val * 100:.2f}%"
                else:
                    val_str = f"{int(val):,}{suffix}"
                print(f"{ip:<20} | {val_str:<18} | {total_req:<15,}")
        print("\n")

    print("\n" + "#" * 65)
    print("           SUSPICIOUS BEHAVIOR ANALYSIS REPORT (99th Percentile)")
    print("#" * 65 + "\n")

    # 1. Total Requests Volume Outliers
    report_indicator("1. High Request Volume (DoS/Scraping)", "total", threshold_total, " reqs")
    
    # 2. Auth Failures Outliers
    report_indicator("2. High Authentication Failures (Brute-Force)", "auth_failures", threshold_auth, " failures")
    
    # 3. Not Found Outliers
    report_indicator("3. High Directory Scanning (404 Fuzzing)", "not_found", threshold_not_found, " hits")
    
    # 4. Error Ratio Outliers
    report_indicator("4. High Error Ratio (Client/Server Errors)", None, threshold_error_ratio, is_ratio=True)
    
    # 5. Bot hits on sensitive endpoints
    report_indicator("5. Automated Bot Activity on Sensitive Paths", "bot_sensitive", threshold_bot_sensitive, " hits")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze access logs to identify suspicious client behavior.")
    parser.add_argument("log_path", type=str, help="Path to the access log file")
    args = parser.parse_args()
    
    analyze_suspicious_behavior(args.log_path)
