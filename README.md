# 🔍 Log Analysis CLI

> A modular Python suite for parsing, analyzing, and detecting security/performance anomalies in web server access logs — streaming line-by-line to keep memory lean even on large files.

---

## 📁 Files

| File | Purpose |
|---|---|
| `main.py` | Unified CLI entry point — runs all 4 analyses in sequence |
| `read_log.py` | Core parser & shared utilities |
| `traffic_analysis.py` | Hourly traffic peaks/valleys + chart generator |
| `traffic_stats.py` | Global request stats, top-N endpoints, error counts |
| `detect_suspicious.py` | 99th-percentile IP anomaly & threat detector |
| `detect_outages.py` | Sliding-window 5xx outage incident tracker |

---

## 🧩 Functions at a Glance

### `read_log.py`
| Function | What it does |
|---|---|
| `LogEntry` | Dataclass holding all parsed fields for a single log line. |
| `parse_line(line)` | Converts a raw log string into a `LogEntry` using a regex against the Combined Log Format. |
| `open_log_file(path)` | Opens a log file, automatically using `gzip.open` if the path ends in `.gz`. |
| `parse_filter_datetime(dt_str)` | Parses a datetime string (`YYYY-MM-DD HH:MM:SS`) into a UTC-aware `datetime` object. |
| `write_output(...)` | Routes results to terminal, `.txt`, or `.json` depending on `--format`. |

### `traffic_analysis.py`
| Function | What it does |
|---|---|
| `analyze_traffic(...)` | Buckets requests by hour, fills zero-traffic gaps, saves a `traffic_chart.png`, and prints/exports the result. |

### `traffic_stats.py`
| Function | What it does |
|---|---|
| `calculate_stats(...)` | Aggregates total requests, unique IPs, 4xx/5xx error counts, and ranks the top-N endpoints by hit count. |

### `detect_suspicious.py`
| Function | What it does |
|---|---|
| `get_percentile(values, p)` | Pure-Python percentile calculation (sorts and indexes into the list). |
| `is_bot_user_agent(ua)` | Returns `True` if the User-Agent matches known bot/tool signatures like `curl`, `wget`, `python-requests`. |
| `analyze_suspicious_behavior(...)` | Flags IPs that exceed the 99th percentile on request volume, 401/403 rate, 404 scanning, error ratio, or bot activity on sensitive paths. |

### `detect_outages.py`
| Function | What it does |
|---|---|
| `detect_5xx_outages(...)` | Groups logs into 1-minute buckets, slides a 5-minute window over them, and reports merged outage intervals where the 5xx rate exceeds the threshold. |

---

## 🚀 How to Run

### `main.py` — Run everything at once

```bash
python3 main.py <log_file> [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `log_path` | *(required)* | Path to the log file (plain or `.gz`) |
| `--top-n N` | `10` | Number of top endpoints to display in the stats report |
| `--start "YYYY-MM-DD HH:MM:SS"` | *(none)* | Filter out entries before this datetime (UTC) |
| `--end "YYYY-MM-DD HH:MM:SS"` | *(none)* | Filter out entries after this datetime (UTC) |

**Example:**
```bash
python3 main.py access.log/access.log --top-n 5 --start "2026-06-01 00:00:00" --end "2026-06-01 23:59:59"
```

> **Note:** Date-only values like `--end "2026-06-01"` resolve to **midnight UTC**, so use `23:59:59` to include the full day.

---

### Individual Scripts

Each script also runs standalone and supports `--format terminal | txt | json`:

```bash
# Test the parser and inspect the first 5 matching entries
python3 read_log.py access.log/access.log

# Hourly traffic chart + analysis
python3 traffic_analysis.py access.log/access.log --format terminal

# Top-5 endpoints + stats for a specific window
python3 traffic_stats.py access.log/access.log --top-n 5 --start "2026-06-01 02:00:00" --end "2026-06-01 05:00:00" --format json

# Flag suspicious IPs
python3 detect_suspicious.py access.log/access.log --format terminal

# Detect 5xx outage incidents
python3 detect_outages.py access.log/access.log --format txt
```
