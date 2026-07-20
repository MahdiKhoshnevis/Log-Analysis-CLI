import argparse
from read_log import parse_filter_datetime
from traffic_stats import calculate_stats
from traffic_analysis import analyze_traffic
from detect_suspicious import analyze_suspicious_behavior
from detect_outages import detect_5xx_outages

DIVIDER = "\n" + "=" * 50 + "\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full log analysis report.")
    parser.add_argument("log_path", type=str, help="Path to the access log file")
    parser.add_argument("--top-n", type=int, default=10, help="Top N endpoints (default: 10)")
    parser.add_argument("--start", type=parse_filter_datetime, help="Start datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_filter_datetime, help="End datetime filter (YYYY-MM-DD HH:MM:SS)")
    args = parser.parse_args()

    kwargs = {"start_time": args.start, "end_time": args.end, "format_opt": "terminal"}

    print(DIVIDER + "  [1/4] TRAFFIC STATISTICS" + DIVIDER)
    calculate_stats(args.log_path, top_n=args.top_n, **kwargs)

    print(DIVIDER + "  [2/4] HOURLY TRAFFIC ANALYSIS" + DIVIDER)
    analyze_traffic(args.log_path, plot=False, **kwargs)

    print(DIVIDER + "  [3/4] SUSPICIOUS BEHAVIOR ANALYSIS" + DIVIDER)
    analyze_suspicious_behavior(args.log_path, **kwargs)

    print(DIVIDER + "  [4/4] SYSTEM OUTAGE DETECTION" + DIVIDER)
    detect_5xx_outages(args.log_path, **kwargs)
