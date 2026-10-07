import os
import sys
import time
import random

# Ensure root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard.alerts.store import AlertStore
from netguard.alerts.manager import AlertManager
from netguard.flow.tracker import FlowTracker
from netguard.detectors.engine import DetectionEngine
from lab.attack_simulator import (
    generate_benign_traffic,
    generate_port_scan_traffic,
    generate_syn_flood_traffic,
    generate_dns_tunnel_traffic,
    generate_arp_spoof_traffic
)


def run_live_generator(db_path: str = "netguard.db", interval: float = 3.0):
    """
    Simulates continuous real-time network traffic and attacks,
    feeding live events into the IDS database every few seconds.
    """
    store = AlertStore(db_path)
    tracker = FlowTracker()
    engine = DetectionEngine()
    manager = AlertManager(cooldown_seconds=15.0)

    print(f"[*] NetGuard Live Traffic Generator started against '{db_path}'")
    print(f"[*] Emitting continuous traffic stream every {interval}s (Press Ctrl+C to stop)...\n")

    attack_generators = [
        ("Port Scan Burst", generate_port_scan_traffic),
        ("SYN Flood Wave", generate_syn_flood_traffic),
        ("DNS Tunneling Chunk", generate_dns_tunnel_traffic),
        ("ARP Poisoning Probe", generate_arp_spoof_traffic),
    ]

    cycle = 0
    minute_accumulator = {}

    while True:
        cycle += 1
        current_time = time.time()
        batch = []

        # Always inject background benign traffic
        batch.extend(generate_benign_traffic(base_ts=current_time, count=random.randint(15, 30)))

        # Periodically inject an attack pattern
        if cycle % 2 == 0:
            attack_name, gen_func = random.choice(attack_generators)
            attack_events = gen_func(base_ts=current_time + 0.1)
            batch.extend(attack_events)
            print(f"[{time.strftime('%X')}] Injected >> {attack_name} ({len(attack_events)} attack packets)")
        else:
            print(f"[{time.strftime('%X')}] Injected >> Normal background traffic ({len(batch)} packets)")

        # Sort batch by timestamp
        batch.sort(key=lambda item: item[0].ts)

        m_ts = int(current_time // 60) * 60
        if m_ts not in minute_accumulator:
            minute_accumulator[m_ts] = {
                "packets": 0, "bytes": 0, "alerts": 0,
                "TCP": 0, "UDP": 0, "ARP": 0, "OTHER": 0
            }
        bucket = minute_accumulator[m_ts]

        # Process packets through IDS engine
        emitted_count = 0
        for ev, _ in batch:
            tracker.process(ev)
            raw_alerts = engine.process(ev)
            emitted = manager.process(raw_alerts)
            if emitted:
                store.save_alerts(emitted)
                emitted_count += len(emitted)

            bucket["packets"] += 1
            bucket["bytes"] += ev.size
            proto = ev.proto if ev.proto in ("TCP", "UDP", "ARP") else "OTHER"
            bucket[proto] += 1

        bucket["alerts"] += emitted_count

        # Update flows and minute stats
        store.save_flows(list(tracker.flows.values()))
        store.record_minute_stats(
            minute_ts=float(m_ts),
            total_packets=bucket["packets"],
            total_bytes=bucket["bytes"],
            alerts_count=bucket["alerts"],
            breakdown={"TCP": bucket["TCP"], "UDP": bucket["UDP"], "ARP": bucket["ARP"], "OTHER": bucket["OTHER"]}
        )

        # Evict idle flows past 60s
        tracker.evict_idle(current_ts=current_time)

        top_talkers = store.get_top_talkers(limit=4)
        talker_summary = ", ".join([f"{t['ip']} ({t['bytes']}B)" for t in top_talkers])
        print(f"[{time.strftime('%X')}] Active Top Talkers >> {talker_summary}")

        time.sleep(interval)


if __name__ == "__main__":
    run_live_generator()
