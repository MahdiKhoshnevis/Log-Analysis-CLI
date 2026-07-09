import time
import argparse
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from read_log import parse_line, open_log_file, parse_filter_datetime, write_output

def analyze_traffic(log_file_path, start_time=None, end_time=None, format_opt="terminal"):
    start_time_perf = time.perf_counter()
    
    # Store counts of requests by hour datetime object
    hourly_counts = {}
    
    # Time format in the log: "01/Jun/2026:00:00:00 +0000"
    time_format = "%d/%b/%Y:%H:%M:%S %z"
    
    print(f"Reading and parsing logs line-by-line from '{log_file_path}'...")
    try:
        with open_log_file(log_file_path) as file:
            for line in file:
                entry = parse_line(line)
                if entry.timestamp and entry.timestamp != "EMPTY_TIME":
                    try:
                        # Parse string to timezone-aware datetime object
                        dt = datetime.strptime(entry.timestamp, time_format)
                        
                        # Apply start/end filters
                        if start_time and dt < start_time:
                            continue
                        if end_time and dt > end_time:
                            continue
                            
                        # Normalize to the beginning of the hour (minute=0, second=0, microsecond=0)
                        hour_dt = dt.replace(minute=0, second=0, microsecond=0)
                        hourly_counts[hour_dt] = hourly_counts.get(hour_dt, 0) + 1
                    except ValueError:
                        # Ignore malformed timestamp entries
                        pass
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return

    if not hourly_counts:
        print("No valid traffic data found matching the criteria.")
        return

    # Find the range of hours (min to max)
    min_hour = min(hourly_counts.keys())
    max_hour = max(hourly_counts.keys())
    
    # Generate all sequential hourly datetimes in between
    all_hours = []
    current_hour = min_hour
    while current_hour <= max_hour:
        all_hours.append(current_hour)
        current_hour += timedelta(hours=1)
        
    # Build complete data including zero-request hours
    final_data = []
    for h in all_hours:
        count = hourly_counts.get(h, 0)
        final_data.append((h, count))
        
    elapsed_time = time.perf_counter() - start_time_perf

    # Build formatted text report
    output_lines = []
    output_lines.append("\n" + "="*45)
    output_lines.append(f"{'Time Bucket':<25} | {'Request Count':<15}")
    output_lines.append("="*45)
    for h, count in final_data:
        time_str = h.strftime("%Y-%m-%d %H:00")
        output_lines.append(f"{time_str:<25} | {count:<15,}")
    output_lines.append("="*45)
    output_lines.append(f"Execution Time: {elapsed_time:.4f} seconds")
    output_lines.append("="*45 + "\n")
    text_report = "\n".join(output_lines)
    
    # Build JSON structured data
    json_data = {
        "execution_time_sec": round(elapsed_time, 4),
        "hourly_traffic": [
            {"time": h.strftime("%Y-%m-%d %H:00"), "count": count}
            for h, count in final_data
        ]
    }
    
    # Handle report output
    write_output(text_report, json_data, format_opt, "traffic_analysis")
    
    # 2. Plot the bar graph with matplotlib
    x_labels = [h.strftime("%Y-%m-%d %H:00") for h, _ in final_data]
    y_values = [count for _, count in final_data]
    
    plt.figure(figsize=(12, 6)) # slightly wider for longer dates
    
    # Render bars with a stylish modern color
    bars = plt.bar(x_labels, y_values, color="#3f51b5", edgecolor="#303f9f", alpha=0.85, width=0.6)
    
    # Customize grid and background
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.gca().set_axisbelow(True)
    
    # Labels and Titles
    plt.title("Hourly Traffic Distribution (Peak & Valleys Analysis)", fontsize=14, fontweight="bold", pad=15)
    plt.xlabel("Hour of the Day", fontsize=11, labelpad=10)
    plt.ylabel("Number of Requests", fontsize=11, labelpad=10)
    
    # Rotate x labels for better date readability
    plt.xticks(rotation=45, ha='right')
    
    # Ensure y-axis starts exactly at 0
    plt.ylim(bottom=0)
    
    # Add values on top of each bar
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, height + max(y_values)*0.01,
                 f"{int(height):,}", ha='center', va='bottom', fontsize=9, fontweight='semibold')
                 
    plt.tight_layout()
    
    # Save the output image
    output_image = "traffic_chart.png"
    plt.savefig(output_image, dpi=150)
    plt.close()
    
    print(f"Success! Bar graph generated and saved to: {output_image}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate hourly traffic distribution from access logs.")
    parser.add_argument("log_path", type=str, help="Path to the access log file (absolute or relative)")
    parser.add_argument("--start", type=parse_filter_datetime, help="Start datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end", type=parse_filter_datetime, help="End datetime filter (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--format", type=str, choices=["terminal", "txt", "json"], default="terminal",
                        help="Output format (default: terminal)")
    args = parser.parse_args()
    
    analyze_traffic(args.log_path, start_time=args.start, end_time=args.end, format_opt=args.format)
