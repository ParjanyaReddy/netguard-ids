import pytest
import time
from netguard.alerts.models import Alert
from netguard.alerts.manager import AlertManager
from netguard.alerts.store import AlertStore
from netguard.flow.tracker import Flow, canonical_flow_key


def test_alert_manager_cooldown_deduplication():
    manager = AlertManager(cooldown_seconds=10.0)

    a1 = Alert(
        alert_type="port_scan",
        severity="medium",
        src="192.168.1.5",
        dst="10.0.0.1",
        description="Scan attempt 1",
        ts=100.0
    )
    # First alert should emit
    assert manager.should_emit(a1) is True

    # Same alert 3 seconds later should be suppressed
    a2 = Alert(
        alert_type="port_scan",
        severity="medium",
        src="192.168.1.5",
        dst="10.0.0.1",
        description="Scan attempt 2",
        ts=103.0
    )
    assert manager.should_emit(a2) is False

    # Different alert type from same source should emit
    a3 = Alert(
        alert_type="syn_flood",
        severity="critical",
        src="192.168.1.5",
        dst="10.0.0.1",
        description="Flood attempt",
        ts=104.0
    )
    assert manager.should_emit(a3) is True

    # After cooldown expires (15s > 10s cooldown)
    a4 = Alert(
        alert_type="port_scan",
        severity="medium",
        src="192.168.1.5",
        dst="10.0.0.1",
        description="Scan attempt 3",
        ts=115.0
    )
    assert manager.should_emit(a4) is True
    # Should record suppressed count
    assert a4.evidence.get("suppressed_repeats_during_cooldown") == 1


def test_alert_store_crud_and_filters():
    store = AlertStore(":memory:")

    # Create alerts with different types and severities
    a1 = Alert(
        id="alert-1",
        alert_type="port_scan",
        severity="medium",
        src="1.1.1.1",
        dst="2.2.2.2",
        description="Port scan 1",
        evidence={"ports": [80, 443]},
        ts=1000.0
    )
    a2 = Alert(
        id="alert-2",
        alert_type="syn_flood",
        severity="critical",
        src="1.1.1.2",
        dst="2.2.2.2",
        description="SYN flood",
        evidence={"half_open": 50},
        ts=1050.0
    )
    a3 = Alert(
        id="alert-3",
        alert_type="port_scan",
        severity="high",
        src="1.1.1.3",
        dst="2.2.2.2",
        description="Port scan 2",
        evidence={"ports": [22, 23]},
        ts=1100.0
    )

    store.save_alerts([a1, a2, a3])

    # All alerts
    all_alerts = store.get_alerts()
    assert len(all_alerts) == 3

    # Filter by alert_type
    scans = store.get_alerts(alert_type="port_scan")
    assert len(scans) == 2

    # Filter by severity
    critical = store.get_alerts(severity="critical")
    assert len(critical) == 1
    assert critical[0]["id"] == "alert-2"
    assert critical[0]["evidence"]["half_open"] == 50

    # Filter by timestamp 'since'
    recent = store.get_alerts(since=1050.0)
    assert len(recent) == 2


def test_alert_store_flows_and_top_talkers():
    store = AlertStore(":memory:")

    f1 = Flow(
        key=canonical_flow_key("10.0.0.1", "10.0.0.2", 1000, 80, "TCP"),
        proto="TCP",
        initiator_ip="10.0.0.1",
        initiator_port=1000,
        responder_ip="10.0.0.2",
        responder_port=80,
        start_ts=100.0,
        last_seen_ts=105.0,
        packets_forward=10,
        bytes_forward=5000,
        packets_reverse=5,
        bytes_reverse=1000,
        tcp_state="ESTABLISHED"
    )

    f2 = Flow(
        key=canonical_flow_key("10.0.0.3", "8.8.8.8", 2000, 53, "UDP"),
        proto="UDP",
        initiator_ip="10.0.0.3",
        initiator_port=2000,
        responder_ip="8.8.8.8",
        responder_port=53,
        start_ts=101.0,
        last_seen_ts=102.0,
        packets_forward=2,
        bytes_forward=200,
        packets_reverse=2,
        bytes_reverse=300
    )

    store.save_flows([f1, f2])

    top_talkers = store.get_top_talkers(limit=5)
    assert len(top_talkers) == 2
    # 10.0.0.1 sent 6000 bytes total, 10.0.0.3 sent 500 bytes total
    assert top_talkers[0]["ip"] == "10.0.0.1"
    assert top_talkers[0]["bytes"] == 6000

    proto_dist = store.get_protocol_distribution()
    assert proto_dist.get("TCP") == 15
    assert proto_dist.get("UDP") == 4


def test_alert_store_minute_statistics():
    store = AlertStore(":memory:")

    store.record_minute_stats(
        minute_ts=60.0,
        total_packets=100,
        total_bytes=50000,
        alerts_count=2,
        breakdown={"TCP": 80, "UDP": 15, "ARP": 5}
    )
    store.record_minute_stats(
        minute_ts=120.0,
        total_packets=150,
        total_bytes=75000,
        alerts_count=5,
        breakdown={"TCP": 120, "UDP": 20, "ARP": 10}
    )

    stats = store.get_minute_stats(limit=10)
    assert len(stats) == 2
    # Ordered DESC by minute_ts
    assert stats[0]["minute_ts"] == 120.0
    assert stats[0]["alerts_count"] == 5
    assert stats[0]["tcp_count"] == 120
    assert stats[1]["minute_ts"] == 60.0
