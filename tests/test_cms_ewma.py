import pytest
from netguard.flow.count_min_sketch import CountMinSketch
from netguard.detectors.port_scan import PortScanDetector
from netguard.parser.decode import PacketEvent


def test_count_min_sketch_basic_add_and_estimate():
    cms = CountMinSketch(width=1024, depth=4, conservative_update=True)

    # Initially zero
    assert cms.estimate("192.168.1.50->10.0.0.1:80") == 0

    # Add counts
    for _ in range(10):
        cms.add("192.168.1.50->10.0.0.1:80")

    cms.add("192.168.1.50->10.0.0.1:443", count=5)

    # Estimate should be >= true count (CMS never underestimates)
    assert cms.estimate("192.168.1.50->10.0.0.1:80") >= 10
    assert cms.estimate("192.168.1.50->10.0.0.1:443") >= 5
    # Unseen key should remain 0 or very small in case of collision
    assert cms.estimate("unseen_endpoint") == 0


def test_count_min_sketch_conservative_update():
    # Test that conservative update mitigates overestimation
    cms_cu = CountMinSketch(width=512, depth=4, conservative_update=True)
    cms_standard = CountMinSketch(width=512, depth=4, conservative_update=False)

    for i in range(100):
        cms_cu.add(f"item_{i % 10}")
        cms_standard.add(f"item_{i % 10}")

    est_cu = cms_cu.estimate("item_0")
    est_std = cms_standard.estimate("item_0")

    assert est_cu >= 10
    assert est_std >= 10
    # CU should be <= or equal to standard CMS
    assert est_cu <= est_std


def test_count_min_sketch_decay_and_clear():
    cms = CountMinSketch(width=512, depth=3)
    cms.add("target", 20)
    assert cms.estimate("target") >= 20

    cms.decay(factor=0.5)
    assert cms.estimate("target") <= 10

    cms.clear()
    assert cms.estimate("target") == 0


def test_count_min_sketch_bounded_memory():
    # Width 2048 x Depth 4: exactly 32 KB
    cms = CountMinSketch(width=2048, depth=4)
    assert cms.memory_bytes == 2048 * 4 * 4


def test_port_scan_ewma_low_and_slow_detection():
    # Configure detector for EWMA detection
    detector = PortScanDetector(
        window_seconds=5.0,
        threshold=10,
        enable_ewma=True,
        slow_scan_threshold=12,
        slow_scan_window=300.0,
        ewma_alpha=0.3
    )

    alerts = []
    # Send 15 SYN probes spaced 1.0 second apart
    # Sliding window is 5.0s, so at any moment in the 5s window there are at most 5 probes (< threshold of 10)
    # Fast window will NEVER fire!
    # But EWMA tracks the sustained stealth scan across 15 seconds!
    base_ts = 1000.0
    for i in range(15):
        ev = PacketEvent(
            ts=base_ts + (i * 1.0),
            src="192.168.1.99",
            dst="10.0.0.1",
            proto="TCP",
            sport=50000 + i,
            dport=1000 + i,
            flags="S",
            size=60
        )
        alerts.extend(detector.process(ev))

    # Should trigger a low-and-slow alert
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "port_scan"
    assert alert.evidence["scan_type"] == "low_and_slow"
    assert alert.evidence["unique_targets"] >= 12
    assert "Low-and-slow" in alert.description
