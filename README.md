# NetGuard IDS

A lightweight Network Traffic Analyzer and Mini Intrusion Detection System (IDS) in Python.

## Features
- **Packet Capture & Decoding**: Live sniffing via Scapy and offline PCAP replay.
- **Layer 2 - Layer 7 Parsing**: Normalizes Ethernet, IPv4, TCP, UDP, DNS, and ARP into unified `PacketEvent` structures.
- **Decoupled Architecture**: Bounded queue mechanism between capture and processing threads to avoid packet loss and unbounded memory consumption.
- **Bidirectional Flow Tracking**: Canonical 5-tuple connection state tracking with forward/reverse byte and packet metrics.
- **TCP State Machine**: Real-time tracking of TCP handshake transitions (`SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`, `RESET`).
- **Configurable Idle Eviction**: Automatic cleanup and garbage collection of inactive network flows.
- **Intrusion Detection Modules**:
  - **Port Scan Detection**: Sliding window tracking distinguishing vertical port scans and horizontal port sweeps.
  - **SYN Flood Detection**: Tracks half-open connection spikes and abnormal SYN/ACK completion ratios.
  - **DNS Tunneling & Data Exfiltration**: Multi-signal scoring utilizing Shannon entropy calculation, long query labels, TXT/NULL record inspections, and burst rates.
  - **ARP Poisoning Detection**: Active IP-to-MAC conflict detection, MITM detection, and default gateway impersonation alerts.
- **Alert Deduplication**: Cooldown-based alert manager suppressing repeated alerts from identical sources while logging burst frequency.
- **SQLite Storage & Analytics**: Thread-safe storage engine persisting security alerts, bidirectional flow summaries, top talker bandwidth metrics, protocol distributions, and rolling time-series statistics.

## Installation
```bash
pip install -r requirements.txt
```

## Running Tests
```bash
pytest tests/
```
