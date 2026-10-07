# NetGuard IDS

A lightweight Network Traffic Analyzer and Mini Intrusion Detection System (IDS) in Python.

## Features
- **Packet Capture & Decoding**: Live sniffing via Scapy and offline PCAP replay.
- **Layer 2 - Layer 7 Parsing**: Normalizes Ethernet, IPv4, TCP, UDP, DNS, and ARP into unified `PacketEvent` structures.
- **Decoupled Architecture**: Bounded queue mechanism between capture and processing threads to avoid packet loss and unbounded memory consumption.
- **Phase 1 Complete**: Core decoding engine with full unit test coverage.

## Installation
```bash
pip install -r requirements.txt
```

## Running Tests
```bash
pytest tests/
```
