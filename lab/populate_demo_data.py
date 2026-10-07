import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard.alerts.store import AlertStore
from netguard.alerts.manager import AlertManager
from netguard.flow.tracker import FlowTracker
from netguard.detectors.engine import DetectionEngine
from lab.attack_simulator import generate_full_test_dataset

def seed_demo_data(db_path: str = "netguard.db"):
    store = AlertStore(db_path)
    tracker = FlowTracker()
    engine = DetectionEngine()
    manager = AlertManager(cooldown_seconds=30.0)

    dataset = generate_full_test_dataset()
    print(f"Processing {len(dataset)} simulated packets into {db_path}...")

    minute_buckets = {}

    for ev, label in dataset:
        # 1. Update flow tracker
        flow = tracker.process(ev)

        # 2. Process detection rules
        raw_alerts = engine.process(ev)
        emitted_alerts = manager.process(raw_alerts)
        if emitted_alerts:
            store.save_alerts(emitted_alerts)

        # 3. Minute stats aggregation
        m_ts = int(ev.ts // 60) * 60
        if m_ts not in minute_buckets:
            minute_buckets[m_ts] = {
                "packets": 0,
                "bytes": 0,
                "alerts": 0,
                "TCP": 0,
                "UDP": 0,
                "ARP": 0,
                "OTHER": 0
            }
        b = minute_buckets[m_ts]
        b["packets"] += 1
        b["bytes"] += ev.size
        b["alerts"] += len(emitted_alerts)
        proto = ev.proto if ev.proto in ("TCP", "UDP", "ARP") else "OTHER"
        b[proto] += 1

    # Save all active flows
    store.save_flows(list(tracker.flows.values()))

    # Save minute stats
    for m_ts, data in minute_buckets.items():
        store.record_minute_stats(
            minute_ts=float(m_ts),
            total_packets=data["packets"],
            total_bytes=data["bytes"],
            alerts_count=data["alerts"],
            breakdown={"TCP": data["TCP"], "UDP": data["UDP"], "ARP": data["ARP"], "OTHER": data["OTHER"]}
        )

    print("Demo data seeded successfully:")
    alerts = store.get_alerts(limit=50)
    talkers = store.get_top_talkers(limit=5)
    print(f"  - Alerts recorded: {len(alerts)}")
    print(f"  - Top talkers: {[t['ip'] for t in talkers]}")

if __name__ == "__main__":
    seed_demo_data()
