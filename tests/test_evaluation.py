import pytest
from netguard.detectors.engine import DetectionEngine
from lab.attack_simulator import (
    generate_benign_traffic,
    generate_port_scan_traffic,
    generate_syn_flood_traffic,
    generate_dns_tunnel_traffic,
    generate_arp_spoof_traffic,
    generate_full_test_dataset,
)
from eval.evaluate import evaluate_engine


def test_attack_simulator_generators():
    benign = generate_benign_traffic(count=10)
    assert len(benign) > 0
    assert all(label == "benign" for _, label in benign)

    scan = generate_port_scan_traffic(num_ports=10)
    assert len(scan) == 10
    assert all(label == "port_scan" for _, label in scan)

    flood = generate_syn_flood_traffic(count=15)
    assert len(flood) == 15
    assert all(label == "syn_flood" for _, label in flood)

    tunnel = generate_dns_tunnel_traffic(count=5)
    assert len(tunnel) == 5
    assert all(label == "dns_tunnel" for _, label in tunnel)

    arp = generate_arp_spoof_traffic()
    assert len(arp) > 0


def test_full_evaluation_pipeline():
    dataset = generate_full_test_dataset()
    assert len(dataset) > 100

    engine = DetectionEngine()
    results = evaluate_engine(dataset, engine)

    assert "metrics" in results
    assert "packets_per_second" in results
    assert results["packets_per_second"] > 0
    assert results["total_packets"] == len(dataset)

    metrics = results["metrics"]
    for atype in ("port_scan", "syn_flood", "dns_tunnel", "arp_spoof"):
        assert atype in metrics
        assert metrics[atype]["precision"] == 1.0
        assert metrics[atype]["recall"] == 1.0
        assert metrics[atype]["f1"] == 1.0
