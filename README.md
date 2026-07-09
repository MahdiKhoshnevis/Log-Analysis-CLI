# Log Analysis & Security Anomaly Detection Suite

This repository contains a modular, high-efficiency, minimal-dependency suite of Python scripts designed to parse, analyze, and detect security/performance anomalies in web server access logs. 

All scripts process logs **line-by-line (streaming)** to maintain low memory usage, ensuring they can handle extremely large files (e.g., gigabytes) without crashing or causing memory starvation.

---

## Workspace Sitemap & Files

* **read_log.py:** Core parser and shared utility module.
* **traffic_analysis.py:** Hourly traffic peaks/valleys evaluator and chart generator.
* **traffic_stats.py:** Global traffic metrics, top N endpoint ranking, and error counts.
* **detect_suspicious.py:** 99th-percentile anomaly and security threat detector.
* **detect_outages.py:** Sliding window 5xx system outage tracker.
* **.gitignore:** Standard git exclusions (untracked caches, PNGs, and report files).

---

## Detailed Script Descriptions & Function Breakdown

### 1. Core Parser Module: `read_log.py`
This script defines the shared logic for parsing access log entries, handling gzip compressed logs, parsing command-line parameters, and formatting output results.

* **LogEntry Class:**
  * **Role:** Lightweight data container representing a parsed log line.
  * **Behavior:** Automatically falls back to `None` if log fields are missing or empty to prevent script execution failures.
* **parse_line(line):**
  * **Role:** Translates a raw log line into a `LogEntry` instance.
  * **Method:** Custom regex pattern mapping the Combined Log Format. It leverages the strict **positional integrity** of standard Nginx/Apache logs (where empty parameters are always substituted with a `-` instead of being left out entirely) to guarantee accurate field extraction. It breaks down the request string by evaluating `method`, `path`, and `protocol` characteristics independently, and strictly validates against actual HTTP methods and status codes.
* **open_log_file(file_path):**
  * **Role:** Transparent file loader.
  * **Method:** Detects `.gz` file extensions and automatically invokes `gzip.open` in text-mode (`"rt"`), allowing transparent line-by-line processing of compressed files.
* **parse_filter_datetime(dt_str):**
  * **Role:** String-to-datetime parser for time filters.
  * **Method:** Supports formats like `YYYY-MM-DD HH:MM:SS` (with or without timezone offset). Automatically treats naive datetimes as UTC-aware.
* **write_output(text_content, json_data, format_opt, default_filename):**
  * **Role:** Report exporter.
  * **Method:** Directs the output depending on formatting arguments (`terminal` print, writing a `.txt` report, or exporting structured metrics to a `.json` file).

---

### 2. Hourly Traffic Analyzer: `traffic_analysis.py`
Aggregates logs by hour to reveal peak traffic volumes and valleys. Generates a visual plot using `matplotlib`.

* **analyze_traffic(log_file_path, start_time, end_time, format_opt):**
  * **Role:** Groups requests chronologically by hour.
  * **Method:** Filters out data outside start/end ranges. It generates all hour blocks between the first and last timestamps (inserting `0` for hours that had no requests) to prevent gaps in charts. Saves the result as `traffic_chart.png` and calls `write_output`.

---

### 3. Log Statistics Report: `traffic_stats.py`
Computes the baseline health of the web server.

* **calculate_stats(log_file_path, top_n, start_time, end_time, format_opt):**
  * **Role:** Aggregates totals, unique users, frequent endpoints, and overall error rate.
  * **Method:** Counts total requests and errors (4xx & 5xx). Adds client IPs to a `set` to get unique user counts. Ranks endpoints using descending sorting (`sorted(..., key=lambda x: x[1], reverse=True)[:top_n]`). Reports overall execution time.

---

### 4. Anomaly Threat Detector: `detect_suspicious.py`
Flags suspicious clients using statistical outlier analysis based on **Option C (99th-Percentile Anomaly Detection)**.

* **get_percentile(values, percentile):**
  * **Role:** Pure-Python percentile computation.
  * **Method:** Sorts values and retrieves the value matching the specified percentile index.
* **is_bot_user_agent(ua):**
  * **Role:** Identifies automated HTTP script libraries.
  * **Method:** Matches headers against bot/tool signatures (e.g., `python-requests`, `curl`, `wget`) or catches completely empty headers.
* **analyze_suspicious_behavior(log_file_path, limit, start_time, end_time, format_opt):**
  * **Role:** Evaluates 5 security threat indicators per IP:
    1. **High Request Volume:** Identifies scraping or application DoS.
    2. **High Authentication Failures:** Identifies brute-force login attempts (401 & 403 status codes).
    3. **Directory Scanning (404 Fuzzing):** Detects path scanning tools.
    4. **High Error Ratio:** Highlights clients experiencing > 99th percentile failure rate.
    5. **Bot Activity on Sensitive Endpoints:** Flags scripted tools hitting paths like `/login`.

---

### 5. Outage Incident Detector: `detect_outages.py`
Pinpoints system failure intervals based on 5xx server status codes.

* **detect_5xx_outages(log_file_path, window_size, threshold_pct, min_requests, start_time, end_time, format_opt):**
  * **Role:** Performs sliding-window 5xx error rate spikes identification.
  * **Method:**
    1. Groups logs into 1-minute fixed buckets.
    2. Runs a sliding window (e.g., 5 minutes) to compute the error rate.
    3. Flags windows where error rate exceeds `threshold_pct` (default: 5.0%) and traffic meets `min_requests`.
    4. Merges overlapping anomalous windows into singular contiguous outage incidents. Reports duration, total errors, average failure rate, and peak error rate.

---

## How to Run the Code

All scripts accept relative or absolute paths, support transparent `.gz` decompression, datetime filtering, customizable Top N outputs, and multiple output format exporters.

```bash
# 1. Inspect first 5 lines
python3 read_log.py access.log/access.log

# 2. Compute hourly traffic and generate a matplotlib chart
python3 traffic_analysis.py access.log/access.log --format terminal

# 3. View the top 5 endpoints and statistics between a specific timeframe
python3 traffic_stats.py access.log/access.log --top-n 5 --start "2026-06-01 02:00:00" --end "2026-06-01 05:00:00" --format json

# 4. Detect top 5 suspicious IP threats
python3 detect_suspicious.py access.log/access.log --top-n 5 --format terminal

# 5. Detect system outages / 5xx incidents
python3 detect_outages.py access.log/access.log --window 5 --threshold 5.0 --format txt
```
