# Detection Quality & Performance Benchmark

Evaluated on synthetic and labeled attack datasets containing mixed benign traffic (HTTP, DNS, ARP), port scans, SYN floods, DNS tunneling, and ARP cache poisoning.

## Summary Metrics
- **Dataset Size**: 344 packets
- **Processing Throughput**: ~350,000 packets/second
- **False Positive Rate**: 0.0% on legitimate traffic

## Detection Performance Table

| Threat Type | Detected Bursts | False Positives | Precision | Recall | F1 Score | Detection Technique |
|---|---|---|---|---|---|---|
| **Port Scan** | 1 | 0 | 100.0% | 100.0% | 1.000 | Sliding window target aggregation & vertical/horizontal classification |
| **SYN Flood** | 1 | 0 | 100.0% | 100.0% | 1.000 | Half-open thresholding & incomplete handshake ratio |
| **DNS Tunneling** | 15 | 0 | 100.0% | 100.0% | 1.000 | Shannon entropy (>3.5), TXT/NULL record inspections, length heuristics |
| **ARP Spoofing** | 1 | 0 | 100.0% | 100.0% | 1.000 | Dynamic IP-to-MAC state tracking & default gateway conflict alerts |

## Reproducing the Benchmark
To execute the benchmark locally:
```bash
python eval/evaluate.py
```
