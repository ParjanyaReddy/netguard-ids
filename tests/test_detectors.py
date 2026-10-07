import pytest
from netguard.parser.decode import PacketEvent
from netguard.detectors import (
    PortScanDetector,
    SynFloodDetector,
    DnsTunnelDetector,
    ArpSpoofDetector,
    DetectionEngine,
    shannon_entropy,
)


def test_shannon_entropy():
    # Empty string
    assert shannon_entropy("") == 0.0

    # Low entropy (uniform characters)
    assert shannon_entropy("aaaaaaa") == 0.0

    # Normal english word
    eng_entropy = shannon_entropy("google")
    assert eng_entropy < 3.0

    # Base64/Hex encoded random string (high entropy)
    high_entropy = shannon_entropy("8f4a3c1e9b2d0f7a6c5e8b1d4f3a2c0e")
    assert high_entropy >= 3.5


def test_port_scan_vertical():
    detector = PortScanDetector(window_seconds=10.0, threshold=10)
    alerts = []

    # Send 12 SYNs to different ports on 1 target
    for port in range(1, 13):
        ev = PacketEvent(
            ts=100.0 + (port * 0.1),
            src="192.168.1.100",
            dst="10.0.0.5",
            proto="TCP",
            sport=40000 + port,
            dport=port,
            flags="S",
            size=60
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "port_scan"
    assert alert.src == "192.168.1.100"
    assert alert.dst == "10.0.0.5"
    assert alert.evidence["scan_type"] == "vertical"
    assert alert.evidence["unique_ports"] >= 10


def test_port_scan_horizontal():
    detector = PortScanDetector(window_seconds=10.0, threshold=10)
    alerts = []

    # Send SYNs to port 22 across 12 different hosts
    for i in range(1, 13):
        ev = PacketEvent(
            ts=100.0 + (i * 0.1),
            src="192.168.1.100",
            dst=f"10.0.0.{i}",
            proto="TCP",
            sport=45000 + i,
            dport=22,
            flags="S",
            size=60
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.evidence["scan_type"] == "horizontal"
    assert alert.evidence["unique_hosts"] >= 10


def test_port_scan_sliding_window_expiration():
    detector = PortScanDetector(window_seconds=5.0, threshold=10)
    alerts = []

    # Send 15 SYNs spaced out by 2 seconds each (rate too slow to breach 5s window)
    for i in range(1, 16):
        ev = PacketEvent(
            ts=100.0 + (i * 2.0),
            src="192.168.1.100",
            dst="10.0.0.5",
            proto="TCP",
            sport=50000 + i,
            dport=i,
            flags="S",
            size=60
        )
        alerts.extend(detector.process(ev))

    assert len(alerts) == 0


def test_syn_flood_detection():
    detector = SynFloodDetector(window_seconds=5.0, threshold_syn_count=15, incomplete_ratio_threshold=0.8)
    alerts = []

    # Attacker sends 20 pure SYNs from spoofed ports to target
    for i in range(20):
        syn_ev = PacketEvent(
            ts=50.0 + (i * 0.05),
            src="192.168.1.200",
            dst="10.0.0.1",
            proto="TCP",
            sport=30000 + i,
            dport=80,
            flags="S",
            size=60
        )
        alerts.extend(detector.process(syn_ev))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "syn_flood"
    assert alert.dst == "10.0.0.1"
    assert alert.severity == "critical"
    assert alert.evidence["half_open_count"] >= 15


def test_syn_flood_normal_traffic_handshakes():
    detector = SynFloodDetector(window_seconds=5.0, threshold_syn_count=15, incomplete_ratio_threshold=0.8)
    alerts = []

    # Send 20 handshakes: SYN followed immediately by ACK
    for i in range(20):
        syn_ev = PacketEvent(
            ts=50.0 + (i * 0.1),
            src="192.168.1.50",
            dst="10.0.0.1",
            proto="TCP",
            sport=20000 + i,
            dport=443,
            flags="S",
            size=60
        )
        detector.process(syn_ev)

        ack_ev = PacketEvent(
            ts=50.0 + (i * 0.1) + 0.01,
            src="10.0.0.1",
            dst="192.168.1.50",
            proto="TCP",
            sport=443,
            dport=20000 + i,
            flags="SA",
            size=60
        )
        alerts.extend(detector.process(ack_ev))

    assert len(alerts) == 0


def test_dns_tunneling_detection():
    detector = DnsTunnelDetector(entropy_threshold=3.5, length_threshold=40, score_threshold=3)

    # Benign DNS query
    benign = PacketEvent(
        ts=1.0,
        src="192.168.1.15",
        dst="8.8.8.8",
        proto="UDP",
        sport=54321,
        dport=53,
        dns_qname="www.google.com",
        dns_qtype=1
    )
    assert len(detector.process(benign)) == 0

    # Tunneling query: long, high entropy, TXT record
    malicious = PacketEvent(
        ts=1.5,
        src="192.168.1.15",
        dst="8.8.8.8",
        proto="UDP",
        sport=54321,
        dport=53,
        dns_qname="a8f9c2d1e0b5a3f7c8d9e2b4a1c0d8e7.tunnel.attacker.com",
        dns_qtype=16  # TXT record
    )
    alerts = detector.process(malicious)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "dns_tunnel"
    assert alert.evidence["entropy"] >= 3.5
    assert alert.evidence["dns_qtype"] == 16


def test_arp_spoof_poisoning_and_gateway():
    detector = ArpSpoofDetector(gateway_ip="192.168.1.1")

    # Initial valid ARP reply: 192.168.1.1 is at AA:AA:AA:AA:AA:AA
    legit_gw = PacketEvent(
        ts=10.0,
        src="192.168.1.1",
        dst="192.168.1.50",
        proto="ARP",
        arp_op=2,
        arp_psrc="192.168.1.1",
        arp_hwsrc="AA:AA:AA:AA:AA:AA"
    )
    assert len(detector.process(legit_gw)) == 0

    # Attacker poisons ARP cache: 192.168.1.1 is now at BB:BB:BB:BB:BB:BB
    poison = PacketEvent(
        ts=12.0,
        src="192.168.1.1",
        dst="192.168.1.50",
        proto="ARP",
        arp_op=2,
        arp_psrc="192.168.1.1",
        arp_hwsrc="BB:BB:BB:BB:BB:BB"
    )
    alerts = detector.process(poison)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "arp_spoof"
    assert alert.severity == "critical"  # Target is default gateway
    assert alert.evidence["is_gateway"] is True
    assert alert.evidence["original_mac"] == "aa:aa:aa:aa:aa:aa"
    assert alert.evidence["spoofed_mac"] == "bb:bb:bb:bb:bb:bb"


def test_arp_spoof_multi_ip_claim():
    detector = ArpSpoofDetector(max_ips_per_mac=2)
    mac = "cc:cc:cc:cc:cc:cc"

    # MAC claims 3 distinct IPs
    for i in range(1, 4):
        ev = PacketEvent(
            ts=20.0 + i,
            src=f"10.0.0.{i}",
            dst="10.0.0.254",
            proto="ARP",
            arp_op=2,
            arp_psrc=f"10.0.0.{i}",
            arp_hwsrc=mac
        )
        alerts = detector.process(ev)
        if i == 3:
            assert len(alerts) == 1
            assert alerts[0].evidence["mac"] == mac
            assert len(alerts[0].evidence["claimed_ips"]) == 3


def test_detection_engine_orchestration():
    engine = DetectionEngine()
    assert "port_scan" in engine.detectors
    assert "syn_flood" in engine.detectors
    assert "dns_tunnel" in engine.detectors
    assert "arp_spoof" in engine.detectors

    # Disable port scan detector and verify it suppresses alerts
    engine.get_detector("port_scan").enabled = False

    scan_pkt = PacketEvent(
        ts=1.0,
        src="192.168.1.99",
        dst="10.0.0.1",
        proto="TCP",
        sport=1234,
        dport=80,
        flags="S"
    )
    alerts = engine.process(scan_pkt)
    assert len(alerts) == 0

    # Re-enable
    engine.get_detector("port_scan").enabled = True
