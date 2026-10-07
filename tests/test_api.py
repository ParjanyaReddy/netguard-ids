import pytest
from fastapi.testclient import TestClient
from netguard.api.main import create_app
from netguard.alerts.store import AlertStore
from netguard.alerts.models import Alert
from netguard.flow.tracker import Flow, canonical_flow_key


@pytest.fixture
def test_app():
    store = AlertStore(":memory:")

    # Populate sample alerts
    a1 = Alert(
        alert_type="port_scan",
        severity="medium",
        src="192.168.1.10",
        dst="10.0.0.1",
        description="Vertical port scan",
        evidence={"ports": [80, 443]},
        ts=100.0
    )
    a2 = Alert(
        alert_type="syn_flood",
        severity="critical",
        src="192.168.1.20",
        dst="10.0.0.1",
        description="SYN flood attack",
        evidence={"half_open": 100},
        ts=105.0
    )
    store.save_alerts([a1, a2])

    # Populate sample flows
    flow = Flow(
        key=canonical_flow_key("192.168.1.10", "10.0.0.1", 5000, 80, "TCP"),
        proto="TCP",
        initiator_ip="192.168.1.10",
        initiator_port=5000,
        responder_ip="10.0.0.1",
        responder_port=80,
        start_ts=100.0,
        last_seen_ts=102.0,
        packets_forward=5,
        bytes_forward=1500,
        packets_reverse=4,
        bytes_reverse=800
    )
    store.save_flow(flow)

    app = create_app(store=store)
    return app


def test_api_health(test_app):
    client = TestClient(test_app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "netguard-ids"


def test_api_get_alerts_and_filters(test_app):
    client = TestClient(test_app)

    # All alerts
    res = client.get("/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) == 2

    # Filter by severity
    res_crit = client.get("/alerts?severity=critical")
    assert res_crit.status_code == 200
    crit_alerts = res_crit.json()
    assert len(crit_alerts) == 1
    assert crit_alerts[0]["alert_type"] == "syn_flood"

    # Filter by type
    res_scan = client.get("/alerts?type=port_scan")
    assert res_scan.status_code == 200
    scan_alerts = res_scan.json()
    assert len(scan_alerts) == 1
    assert scan_alerts[0]["severity"] == "medium"


def test_api_stats_endpoints(test_app):
    client = TestClient(test_app)

    # Top talkers
    res_talkers = client.get("/stats/top-talkers")
    assert res_talkers.status_code == 200
    talkers = res_talkers.json()
    assert len(talkers) == 1
    assert talkers[0]["ip"] == "192.168.1.10"
    assert talkers[0]["bytes"] == 2300

    # Protocols
    res_proto = client.get("/stats/protocols")
    assert res_proto.status_code == 200
    proto = res_proto.json()
    assert proto.get("TCP") == 9

    # Summary
    res_sum = client.get("/stats/summary")
    assert res_sum.status_code == 200
    summary = res_sum.json()
    assert summary["total_alerts"] == 2
    assert summary["severities"]["critical"] == 1
    assert summary["severities"]["medium"] == 1


def test_api_serve_dashboard(test_app):
    client = TestClient(test_app)
    response = client.get("/")
    assert response.status_code == 200
    assert "NetGuard IDS" in response.text
