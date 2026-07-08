import os
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from read_log import parse_line

def analyze_traffic(log_file_path):
    
    # Store counts of requests by hour datetime object
    hourly_counts = {}
    
    # Time format in the log: "01/Jun/2026:00:00:00 +0000"
    time_format = "%d/%b/%Y:%H:%M:%S %z"
    
    print(f"Reading and parsing logs line-by-line from '{log_file_path}'...")
    try:
        with open(log_file_path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                entry = parse_line(line)
                if entry.timestamp != "EMPTY_TIME":
                    try:
                        # Parse string to timezone-aware datetime object
                        dt = datetime.strptime(entry.timestamp, time_format)
                        # Normalize to the beginning of the hour (minute=0, second=0, microsecond=0)
                        hour_dt = dt.replace(minute=0, second=0, microsecond=0)
                        hourly_counts[hour_dt] = hourly_counts.get(hour_dt, 0) + 1
                    except Exception:
                        # Ignore malformed timestamp entries
                        pass
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return

    if not hourly_counts:
        print("No valid traffic data found.")
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
        
    # 1. Print formatted text-based table
    print("\n" + "="*45)
    print(f"{'Time Bucket (UTC)':<25} | {'Request Count':<15}")
    print("="*45)
    for h, count in final_data:
        time_str = h.strftime("%Y-%m-%d %H:00")
        print(f"{time_str:<25} | {count:<15,}")
    print("="*45 + "\n")
    
    # 2. Plot the bar graph with matplotlib
    x_labels = [h.strftime("%H:00") for h, _ in final_data]
    y_values = [count for _, count in final_data]
    
    plt.figure(figsize=(10, 6))
    
    # Render bars with a stylish modern color
    bars = plt.bar(x_labels, y_values, color="#3f51b5", edgecolor="#303f9f", alpha=0.85, width=0.6)
    
    # Customize grid and background
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.gca().set_axisbelow(True)
    
    # Labels and Titles
    plt.title("Hourly Traffic Distribution (Peak & Valleys Analysis)", fontsize=14, fontweight="bold", pad=15)
    plt.xlabel("Hour of the Day (01-Jun-2026)", fontsize=11, labelpad=10)
    plt.ylabel("Number of Requests", fontsize=11, labelpad=10)
    
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
    import argparse

    parser = argparse.ArgumentParser(description="Generate hourly traffic distribution from access logs.")
    parser.add_argument("log_path", type=str, help="Path to the access log file (absolute or relative)")
    args = parser.parse_args()
    
    analyze_traffic(args.log_path)

