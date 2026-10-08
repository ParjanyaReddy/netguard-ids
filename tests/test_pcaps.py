import os
import pytest
from netguard.capture.pcap_reader import PcapFileCapture
from netguard.detectors.engine import DetectionEngine
from netguard.detectors import (
    PortScanDetector,
    SynFloodDetector,
    DnsTunnelDetector,
    ArpSpoofDetector,
)

PCAPS_DIR = os.path.join(os.path.dirname(__file__), "pcaps")


def replay_pcap_through_engine(pcap_filename: str, engine: DetectionEngine):
    pcap_path = os.path.join(PCAPS_DIR, pcap_filename)
    reader = PcapFileCapture(pcap_path)
    reader.process()

    all_alerts = []
    while True:
        ev = reader.get_event(timeout=0.01)
        if ev is None:
            break
        alerts = engine.process(ev)
        if alerts:
            all_alerts.extend(alerts)

    return all_alerts


def test_pcap_benign_traffic():
    engine = DetectionEngine([
        PortScanDetector(window_seconds=10.0, threshold=15),
        SynFloodDetector(window_seconds=5.0, threshold_syn_count=30),
        DnsTunnelDetector(score_threshold=3),
        ArpSpoofDetector(gateway_ip="192.168.1.1"),
    ])
    alerts = replay_pcap_through_engine("benign_traffic.pcap", engine)
    assert len(alerts) == 0, f"Expected 0 alerts for benign traffic, got: {alerts}"


def test_pcap_port_scan():
    engine = DetectionEngine([
        PortScanDetector(window_seconds=10.0, threshold=15),
    ])
    alerts = replay_pcap_through_engine("port_scan.pcap", engine)
    assert len(alerts) >= 1
    types = [a.alert_type for a in alerts]
    assert "port_scan" in types
    assert alerts[0].src == "10.0.0.99"
    assert alerts[0].evidence["scan_type"] == "vertical"


def test_pcap_syn_flood():
    engine = DetectionEngine([
        SynFloodDetector(window_seconds=5.0, threshold_syn_count=30, incomplete_ratio_threshold=0.8),
    ])
    alerts = replay_pcap_through_engine("syn_flood.pcap", engine)
    assert len(alerts) >= 1
    types = [a.alert_type for a in alerts]
    assert "syn_flood" in types
    assert alerts[0].dst == "192.168.1.10"
    assert alerts[0].severity == "critical"


def test_pcap_dns_tunnel():
    engine = DetectionEngine([
        DnsTunnelDetector(score_threshold=3, entropy_threshold=3.5),
    ])
    alerts = replay_pcap_through_engine("dns_tunnel.pcap", engine)
    assert len(alerts) >= 1
    types = [a.alert_type for a in alerts]
    assert "dns_tunnel" in types
    assert alerts[0].src == "192.168.1.105"


def test_pcap_arp_spoof():
    engine = DetectionEngine([
        ArpSpoofDetector(gateway_ip="192.168.1.1"),
    ])
    alerts = replay_pcap_through_engine("arp_spoof.pcap", engine)
    assert len(alerts) >= 1
    types = [a.alert_type for a in alerts]
    assert "arp_spoof" in types
    assert alerts[0].src == "192.168.1.1"
    assert alerts[0].severity == "critical"
    assert "TARGET IS DEFAULT GATEWAY" in alerts[0].description
