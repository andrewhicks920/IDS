# Proof of Concept Network Intrusion Detection System

A network packet analyzer and real-time intrusion detection system built in Python using Scapy. Captures live network traffic, detects attack patterns using sliding time-window algorithms, streams alerts instantly to a browser dashboard over WebSocket, and generates standalone HTML security reports.

---

## Features

| Module                          | Detection Logic                                                                                                                                                 |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Port Scan Detection**         | Tracks unique destination ports per source IP in a sliding time window. Triggers on 15+ unique SYN packets across different ports within 10 seconds.            |
| **Brute Force Detection**       | Monitors connection frequency to authentication services (SSH, FTP, RDP, VNC, SMTP). Triggers on 5+ attempts within 30 seconds from a single source.            |
| **Data Exfiltration Detection** | Measures cumulative outbound bytes per source IP per minute. Triggers at 5 MB/min threshold.                                                                    |
| **ICMP Flood Detection**        | Counts ICMP packets per second per source IP. Triggers at 50 packets/sec.                                                                                       |
| **DNS Anomaly Detection**       | Monitors DNS query rate per source. Abnormally high rates may indicate DNS tunneling or Domain Generation Algorithm (DGA) activity. Triggers at 30 queries/sec. |

---

## Tech Stack

- **Python 3.11.9+**
- **Scapy** — Raw packet capture and protocol dissection
- **websockets** — Real-time alert streaming to browser dashboard
- **asyncio + threading** — Concurrent packet capture and WebSocket server
- **JSON** — Structured persistent alert storage
- **HTML/CSS/JS** — Self-contained browser dashboard

---

## Project Structure

```
ids/
├── ids_server.py     # Entry point — WebSocket server + IDS engine bridge
├── ids_engine.py     # Core detection engine (Scapy packet analysis)
├── ids_logger.py     # Alert logger + standalone HTML report generator
├── dashboard.html    # Real-time browser dashboard (WebSocket client)
├── alerts.json       # Persistent alert log (auto-generated)
└── README.md
```

---

## Setup

### 1. Install dependencies

```bash
pip install scapy websockets
```

> Scapy requires root/admin privileges for live packet capture.

### 2. Find your network interface

```bash
# macOS
ifconfig

# Linux
ip link
```

Common values: `en0` (macOS WiFi), `eth0` (Linux ethernet), `lo0` / `lo` (loopback).

> **macOS note:** Use `lo0` to capture localhost traffic (SSH brute force tests, local connections). Use `en0` for external traffic (HTTPS, DNS, inbound connections from other devices). There is no single interface that captures both simultaneously without code modification.

---

## Running the IDS

### Live capture

Open two terminal windows.

**Terminal 1 — start the IDS server:**

```bash
sudo python ids_server.py --interface en0
```

This starts Scapy packet capture on the specified interface, launches a WebSocket server at `ws://localhost:8765`, and auto-opens `dashboard.html` in your browser.

**Terminal 2 — open the dashboard:**

If the dashboard did not auto-open, open `dashboard.html` directly in your browser (double-click the file in Finder or your file manager). Then click **Connect Live Engine** in the sidebar.

The dashboard will connect to the WebSocket server and begin displaying real alerts as they are detected.

### Simulation mode (no root required)

```bash
python ids_server.py --simulate
```

Generates realistic synthetic attack traffic — port scans, brute force attempts, data exfiltration, ICMP floods, and DNS anomalies. Useful for demos without needing a live network or root privileges.

### Generate a standalone HTML report

```bash
python ids_engine.py --report
```

Reads from `alerts.json` and produces `ids_report.html` — a fully self-contained report with no external dependencies that can be opened in any browser or emailed as a deliverable.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   ids_server.py                      │
│                                                      │
│   ┌─────────────────────┐   ┌─────────────────────┐  │
│   │  IDSEngineWith      │   │  IDSWebSocket       │  │
│   │  WebSocket          │──▶│  Server             │  │
│   │  (ids_engine.py)    │   │  ws://localhost:8765│  │
│   └──────────┬──────────┘   └──────────┬──────────┘  │
│              │                         │             │
│       Scapy sniff()             asyncio + broadcast  │
│       (background thread)       (main thread)        │
└──────────────┼─────────────────────────┼─────────────┘
               │                         │
         Network packets           WebSocket frames
               │                         │
        ┌──────▼──────┐           ┌───────▼───────┐
        │ alerts.json │           │ dashboard.html│
        │ (disk log)  │           │ (browser)     │
        └─────────────┘           └───────────────┘
```

**How it works:**

1. Scapy captures packets on the specified interface in a background thread
2. Each packet is analyzed by five independent detection modules
3. When a threshold is crossed, `_emit_alert()` fires simultaneously: writing to `alerts.json`, printing to the terminal, and pushing a WebSocket message to all connected dashboards
4. A separate stats thread broadcasts packet counts to the dashboard every 2 seconds
5. The dashboard renders incoming alerts in real time, tagged `LIVE` to distinguish them from simulated data

---

## CLI Reference

### ids_server.py (primary entry point)

```
--interface / -i    Network interface to sniff (e.g. en0, eth0, lo0)
--simulate  / -s    Run in simulation mode — no root or interface required
--output    / -o    Alert log file (default: alerts.json)
--port      / -p    WebSocket server port (default: 8765)
--host              WebSocket server host (default: localhost)
--no-browser        Don't auto-open dashboard.html in the browser
```

### ids_engine.py (standalone, no WebSocket)

```
--interface / -i    Network interface to sniff
--simulate  / -s    Run in simulation mode
--output    / -o    Alert log file (default: alerts.json)
--report    / -r    Generate ids_report.html from alerts.json and exit
```

---

## Detection Thresholds

All thresholds are configurable in `ids_engine.py` under the `THRESHOLDS` dictionary:

```python
THRESHOLDS = {
    "port_scan_unique_ports":   15,       # unique ports within window = scan
    "port_scan_window_sec":     10,
    "brute_force_attempts":     5,        # connection attempts within window
    "brute_force_window_sec":   30,
    "exfil_bytes_per_min":      5_000_000,  # 5 MB/min outbound
    "icmp_flood_per_sec":       50,
    "dns_queries_per_sec":      30,
}
```

> **Tuning note:** Ports 80 and 443 are excluded from brute force detection by default. Normal HTTPS traffic generates enough connections to trigger false positives on home networks. Real-world brute force against web services requires payload inspection beyond connection counting.

---

## Alert Format

Every alert is appended to `alerts.json` as a structured JSON record:

```json
{
  "record_type": "alert",
  "type": "BRUTE_FORCE",
  "severity": "CRITICAL",
  "src_ip": "45.33.32.156",
  "dst_ip": "*",
  "timestamp": "2025-03-11T14:23:01.443",
  "details": {
    "service": "SSH",
    "port": 22,
    "attempts_in_window": 5,
    "window_seconds": 30
  }
}
```

---

## Simulating Attacks for Testing

### Brute force (SSH) — use loopback interface

```bash
# Terminal 1
sudo python ids_server.py --interface lo0

# Terminal 2
for i in {1..10}; do ssh wronguser@localhost; done
```

### Port scan — use nmap against your router

```bash
# Install nmap (macOS)
brew install nmap

# Scan your router — traffic passes through en0
nmap -sS 192.168.1.1
```

---

## Implementation Notes

- **Thread-safe state** — all shared detection state is protected with `threading.Lock()`
- **Sliding time windows** — brute force and rate-based detectors use `collections.deque` for O(1) window management, purging expired timestamps on every packet
- **Alert deduplication** — alerts fire at exactly the threshold count using `==` comparison, preventing alert storms on sustained attacks
- **Stateless packet processing** — raw packet data is never retained; only derived counters and timestamps are stored in memory
- **WebSocket thread safety** — alerts generated on the Scapy capture thread are scheduled onto the asyncio event loop using `run_coroutine_threadsafe`, ensuring no race conditions between threads
