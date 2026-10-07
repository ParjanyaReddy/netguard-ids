# NetGuard IDS

A lightweight Network Traffic Analyzer and Mini Intrusion Detection System (IDS) in Python.

## Features
- **Packet Capture & Decoding**: Live sniffing via Scapy and offline PCAP replay.
- **Layer 2 - Layer 7 Parsing**: Normalizes Ethernet, IPv4, TCP, UDP, DNS, and ARP into unified `PacketEvent` structures.
- **Decoupled Architecture**: Bounded queue mechanism between capture and processing threads to avoid packet loss and unbounded memory consumption.
- **Bidirectional Flow Tracking**: Canonical 5-tuple connection state tracking with forward/reverse byte and packet metrics.
- **TCP State Machine**: Real-time tracking of TCP handshake transitions (`SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`, `RESET`).
- **Configurable Idle Eviction**: Automatic cleanup and garbage collection of inactive network flows.

## Installation
```bash
pip install -r requirements.txt
```

## Running Tests
```bash
pytest tests/
```
