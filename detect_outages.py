import time
import argparse
from datetime import datetime, timedelta
from read_log import parse_line, open_log_file, parse_filter_datetime, write_output

WINDOW_SIZE = 5       # Sliding window size in minutes
THRESHOLD_PCT = 5.0   # Error rate threshold percentage
MIN_REQUESTS = 10     # Min requests in window to trigger anomaly

def detect_5xx_outages(log_file_path, start_time=None, end_time=None, format_opt="terminal"):
    start_time_perf = time.perf_counter()
    
    window_size = WINDOW_SIZE
    threshold_pct = THRESHOLD_PCT
    min_requests = MIN_REQUESTS
    
    # minute_stats structure: { minute_dt: {'total': int, '5xx': int} }
    minute_stats = {}
    time_format = "%d/%b/%Y:%H:%M:%S %z"
    
    print(f"Reading logs and aggregating 5xx counts by minute from '{log_file_path}'...")
    try:
        with open_log_file(log_file_path) as file:
            for line in file:
                entry = parse_line(line)
                
                if entry.timestamp is None:
                    continue
                
                try:
                    dt = datetime.strptime(entry.timestamp, time_format)
                    
                    # Apply start/end filters
                    if start_time and dt < start_time:
                        continue
                    if end_time and dt > end_time:
                        continue
                        
                    # Round to the minute
                    min_dt = dt.replace(second=0, microsecond=0)
                    
                    if min_dt not in minute_stats:
                        minute_stats[min_dt] = {"total": 0, "5xx": 0}
                    
                    minute_stats[min_dt]["total"] += 1
                    
                    # Safely handle status
                    if entry.status is not None and 500 <= entry.status <= 599:
                        minute_stats[min_dt]["5xx"] += 1
                            
                except ValueError:
                    continue
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return

    if not minute_stats:
        print("No traffic data found matching the filter criteria.")
        return

    # Generate sequential list of minutes between min and max minute
    min_minute = min(minute_stats.keys())
    max_minute = max(minute_stats.keys())
    
    minutes_list = []
    curr = min_minute
    while curr <= max_minute:
        minutes_list.append(curr)
        curr += timedelta(minutes=1)
        
    # Standardize data: fill missing minutes with 0
    clean_stats = []
    for m in minutes_list:
        clean_stats.append(minute_stats.get(m, {"total": 0, "5xx": 0}))

    # Calculate sliding window metrics
    anomalies = [False] * len(minutes_list)
    window_rates = [0.0] * len(minutes_list)
    window_totals = [0] * len(minutes_list)
    window_5xxs = [0] * len(minutes_list)
    
    threshold_rate = threshold_pct / 100.0

    for i in range(len(minutes_list)):
        # Sum counts inside the window [i, i + window_size)
        total_in_window = 0
        fivexx_in_window = 0
        for j in range(i, min(i + window_size, len(minutes_list))):
            total_in_window += clean_stats[j]["total"]
            fivexx_in_window += clean_stats[j]["5xx"]
            
        rate = (fivexx_in_window / total_in_window) if total_in_window > 0 else 0.0
        
        window_rates[i] = rate
        window_totals[i] = total_in_window
        window_5xxs[i] = fivexx_in_window
        
        # Anomaly criteria: rate exceeds threshold and min_requests are met
        if rate >= threshold_rate and total_in_window >= min_requests:
            anomalies[i] = True

    # Merge contiguous/overlapping anomalous windows into unified outages
    outages = []
    current_outage = None
    
    for i, is_anomaly in enumerate(anomalies):
        curr_min = minutes_list[i]
        
        if is_anomaly:
            win_end = curr_min + timedelta(minutes=window_size)
            if current_outage is None:
                current_outage = {
                    "start": curr_min,
                    "end": win_end,
                    "peak_rate": window_rates[i]
                }
            else:
                if curr_min <= current_outage["end"]:
                    # Extend and merge
                    current_outage["end"] = win_end
                    current_outage["peak_rate"] = max(current_outage["peak_rate"], window_rates[i])
                else:
                    outages.append(current_outage)
                    current_outage = {
                        "start": curr_min,
                        "end": win_end,
                        "peak_rate": window_rates[i]
                    }
        else:
            if current_outage is not None and curr_min >= current_outage["end"]:
                outages.append(current_outage)
                current_outage = None
                
    if current_outage is not None:
        outages.append(current_outage)

    # Compute exact request and 5xx counts for each merged outage period
    for outage in outages:
        o_start = outage["start"]
        o_end = outage["end"]
        
        o_total = 0
        o_5xx = 0
        curr_m = o_start
        while curr_m < o_end:
            stat = minute_stats.get(curr_m, {"total": 0, "5xx": 0})
            o_total += stat["total"]
            o_5xx += stat["5xx"]
            curr_m += timedelta(minutes=1)
            
        outage["total_reqs"] = o_total
        outage["total_5xx"] = o_5xx
        outage["average_rate"] = (o_5xx / o_total) if o_total > 0 else 0.0

    elapsed_time = time.perf_counter() - start_time_perf

    # Build report text content
    if not outages:
        outage_rows = "No system outage periods detected matching the criteria.\n"
    else:
        rows = ""
        for out in outages:
            avg_str = f"{out['average_rate'] * 100:.1f}%"
            peak_str = f"{out['peak_rate'] * 100:.1f}%"
            dur_str = f"{int((out['end'] - out['start']).total_seconds() / 60)} mins"
            rows += (
                f"{out['start'].strftime('%Y-%m-%d %H:%M'):<17} | "
                f"{out['end'].strftime('%Y-%m-%d %H:%M'):<17} | "
                f"{dur_str:<8} | "
                f"{out['total_reqs']:<9,} | "
                f"{out['total_5xx']:<9,} | "
                f"{avg_str:<8} | "
                f"{peak_str:<9}\n"
            )
        outage_rows = (
            f"{'Start Time':<17} | {'End Time':<17} | {'Duration':<8} | {'Total Req':<9} | {'5xx Count':<9} | {'Avg Rate':<8} | {'Peak Rate':<9}\n"
            + "-"*50 + "\n"
            + rows
        )

    text_report = (
        "\n" + "="*50 + "\n"
        "                SYSTEM 5xx OUTAGE & INCIDENT REPORT\n"
        + f"                Execution Time: {elapsed_time:.4f} seconds\n"
        + "="*50 + "\n"
        + f"Parameters: Window Size = {window_size}m | Threshold = {threshold_pct}% | Min Requests = {min_requests}\n"
        + "-"*50 + "\n"
        + outage_rows
        + "="*50 + "\n"
    )
    
    # Build JSON structure
    json_data = {
        "execution_time_sec": round(elapsed_time, 4),
        "incidents": [
            {
                "start_time": out["start"].strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": out["end"].strftime("%Y-%m-%d %H:%M:%S"),
                "duration_minutes": int((out["end"] - out["start"]).total_seconds() / 60),
                "total_requests": out["total_reqs"],
                "total_5xx_errors": out["total_5xx"],
                "average_error_rate_pct": round(out["average_rate"] * 100, 2),
                "peak_error_rate_pct": round(out["peak_rate"] * 100, 2)
            }
            for out in outages
        ]
    }
    
    write_output(text_report, json_data, format_opt, "system_outages")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Identify periods of elevated 5xx server errors.")
    parser.add_argument("log_path", type=str, help="Path to the access log file")
    parser.add_argument("--start", type=parse_filter_datetime, help="Start datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_filter_datetime, help="End datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--format", type=str, choices=["terminal", "txt", "json"], default="terminal",
                        help="Output format (default: terminal)")
    args = parser.parse_args()

    detect_5xx_outages(args.log_path, start_time=args.start, end_time=args.end, format_opt=args.format)
