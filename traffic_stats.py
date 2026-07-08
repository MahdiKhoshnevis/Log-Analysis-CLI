import os
from read_log import parse_line

def calculate_stats():
    log_file_path = os.path.join("access.log", "access.log")
    
    total_requests = 0
    unique_ips = set()
    path_counts = {}
    error_requests = 0
    
    print("Reading and aggregating log stats line-by-line...")
    try:
        with open(log_file_path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                entry = parse_line(line)
                
                # We skip completely empty lines (where all attributes are defaults/empty)
                # but if it has any parsed content, it's counted as a request
                if entry.ip == "EMPTY_IP" and entry.timestamp == "EMPTY_TIME":
                    continue
                
                total_requests += 1
                
                # Track unique IPs
                if entry.ip != "EMPTY_IP":
                    unique_ips.add(entry.ip)
                
                # Track endpoint/path counts
                if entry.path != "EMPTY_PATH":
                    path_counts[entry.path] = path_counts.get(entry.path, 0) + 1
                    
                # Track 4xx and 5xx errors
                # Status code is a string, e.g. "404", "500", "200"
                if entry.status != "EMPTY_STATUS":
                    if entry.status.startswith(("4", "5")):
                        error_requests += 1

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return

    if total_requests == 0:
        print("No requests found in the log file.")
        return

    # Calculate unique IP count
    total_unique_ips = len(unique_ips)
    
    # Sort paths by count descending to find top 10
    top_endpoints = sorted(path_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    
    # Calculate error rate percentage
    error_rate = (error_requests / total_requests) * 100

    # Print report
    print("\n" + "="*50)
    print("                 LOG ANALYSIS REPORT")
    print("="*50)
    print(f"Total Requests:           {total_requests:,}")
    print(f"Unique Client IPs:        {total_unique_ips:,}")
    print(f"Error Rate (4xx & 5xx):   {error_rate:.2f}% ({error_requests:,} requests)")
    print("="*50)
    print("Top 10 Most Frequent Endpoints:")
    print("-"*50)
    for rank, (path, count) in enumerate(top_endpoints, 1):
        print(f"{rank:2d}. {path:<30} | {count:<10,} requests")
    print("="*50 + "\n")

if __name__ == "__main__":
    calculate_stats()
