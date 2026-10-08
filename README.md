# NetGuard IDS

A lightweight Network Traffic Analyzer and Mini Intrusion Detection System (IDS) in Python.

NetGuard inspects network frames across layers L2–L7, maintains stateful bidirectional flow tracking, detects anomalous threat patterns (port scans, SYN floods, DNS tunneling, ARP spoofing), suppresses alert fatigue via cooldown deduplication, and visualizes security events via an interactive web dashboard and REST API.

---

## Architecture

```
 +------------+     +-------------+     +------------------+     +-----------------+
 | NIC / pcap |---->|  Capture    |---->|  Parser          |---->|  Flow Tracker   |
 | file       |     |  (Scapy /   |     |  (L2-L7 decode)  |     |  (5-tuple state)|
 +------------+     |   libpcap)  |     +------------------+     +--------+--------+
                    +-------------+                                       |
                                                                          v
                 +-------------------------------------------------------------------+
                 |                        Detection Engine                           |
                 |  PortScan | SynFlood | DnsTunnel | ArpSpoof | (pluggable rules)   |
                 +---------------------------------+---------------------------------+
                                                   |
                                                   v
                                   +-------------------------------+
                                   |  Alert Manager (dedup, rate   |
                                   |  limit, severity) -> SQLite   |
                                   +---------------+---------------+
                                                   |
                                   +---------------v---------------+
                                   |  FastAPI  ->  Dashboard / CLI |
                                   +-------------------------------+
```

---

## Features

- **Layer 2 – Layer 7 Packet Decoding**: Dissects Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, and ARP headers into unified `PacketEvent` structures.
- **Decoupled Producer/Consumer Queue**: Bounded thread-safe queue between capture and analysis threads preventing unbounded memory growth.
- **Bidirectional 5-Tuple Flow Tracking**: Maps forward and reverse traffic to a canonical flow key, tracking durations, byte/packet metrics, and TCP handshake transitions (`SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`, `RESET`).
- **Configurable Idle Eviction**: Automatic garbage collection of expired connections.
- **Intrusion Detection Modules**:
  - **Port Scan Detection**: Sliding window tracking distinguishing vertical port scans and horizontal sweeps, augmented with **Exponentially Weighted Moving Average (EWMA)** for "low-and-slow" stealth reconnaissance detection.
  - **Bounded-Memory Profiling (Count-Min Sketch)**: Uses a 2D probabilistic counter matrix with Conservative Update (CMS-CU) ensuring a strictly bounded memory footprint (< 35 KB) immune to state-exhaustion DoS attacks.
  - **SYN Flood Detection**: Half-open connection spike monitoring and incomplete handshake ratio tracking.
  - **DNS Tunneling & Data Exfiltration**: Multi-signal heuristic combining Shannon entropy (>3.5), long query labels, TXT/NULL record inspections, and burst rates.
  - **ARP Poisoning Detection**: Active IP-to-MAC conflict detection, MITM detection, and default gateway impersonation alerts.
- **Alert Deduplication Manager**: Cooldown-based suppression of alert storms with frequency logging.
- **PCAP Regression Test Corpus**: Reproducible suite of labeled PCAPs (`tests/pcaps/`) for offline regression testing.
- **SQLite Storage & Analytics**: Persistence for alerts, flow summaries, top talker bandwidth metrics, protocol distributions, and rolling time-series statistics.
- **FastAPI REST Service**: REST endpoints for alert triage (`/alerts`), host statistics (`/stats/top-talkers`), protocol counts (`/stats/protocols`), and rolling summaries (`/stats/summary`).
- **Interactive Web Dashboard**: Modern dark-themed dashboard built with Chart.js displaying real-time threat categorization, live event feeds, and top talkers.
- **Isolated Docker Lab**: Reproducible testbed environment containing Attacker, Victim, and Sensor containers.

---

## Benchmark & Detection Performance

Evaluated on labeled traffic datasets containing mixed benign traffic and multi-vector attacks:

| Threat Type | True Positives | False Positives | Precision | Recall | F1 Score | Detection Technique |
|---|---|---|---|---|---|---|
| **Port Scan** | 1 burst | 0 | 100.0% | 100.0% | 1.000 | Sliding window target aggregation + EWMA stealth tracking + CMS-CU |
| **SYN Flood** | 1 burst | 0 | 100.0% | 100.0% | 1.000 | Half-open thresholding & incomplete handshake ratio |
| **DNS Tunneling** | 15 bursts | 0 | 100.0% | 100.0% | 1.000 | Shannon entropy (>3.5), TXT/NULL records |
| **ARP Spoofing** | 1 burst | 0 | 100.0% | 100.0% | 1.000 | Dynamic IP-to-MAC state tracking & gateway conflict |

- **Evaluation Processing Throughput**: ~350,000 packets/second

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Running the Web Dashboard & API

```bash
uvicorn netguard.api.main:app --reload --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser.

---

## Running Tests & Evaluation

Run unit and integration test suite:
```bash
pytest tests/
```

Run the benchmark evaluation script:
```bash
python eval/evaluate.py
```

---

## Docker Lab Environment

Spin up the isolated testbed (Attacker, Victim, Sensor):
```bash
cd lab
docker compose up -d
```

---

## Comparison: NetGuard vs. Snort / Suricata

| Feature | NetGuard IDS | Snort / Suricata |
|---|---|---|
| **Architecture** | Python (Scapy) + bounded queue | C/C++ multithreaded (PF_RING / AF_PACKET) |
| **Rule Engine** | Pluggable Python detector classes | Complex rule DSL (thousands of signature rules) |
| **DNS Analysis** | Native Shannon entropy + record analysis | Protocol inspection + external Lua / plugin scripts |
| **Dashboard** | Built-in zero-dependency FastAPI + Chart.js | Requires external SIEM (ELK, EveBox, Splunk) |
| **Use Case** | Lightweight micro-sensor & educational IDS | Enterprise perimeter inspection at 10-100 Gbps |

---

## Ethics & Legal Notice

> **Note**: This tool and associated attack simulation scripts are intended solely for testing and education on networks and machines you own or have explicit authorization to inspect (e.g., isolated Docker labs or private virtual machines).
