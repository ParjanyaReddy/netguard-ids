from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NetGuardConfig:
    db_path: str = "netguard.db"
    interface: Optional[str] = None
    bpf_filter: str = "tcp or udp or arp"
    capture_queue_size: int = 10000
    flow_idle_timeout: float = 60.0
    flow_tcp_established_timeout: float = 300.0
    alert_cooldown_seconds: float = 60.0
    gateway_ip: Optional[str] = None

    # Detector thresholds
    port_scan_window: float = 10.0
    port_scan_threshold: int = 15
    syn_flood_window: float = 5.0
    syn_flood_threshold: int = 40
    syn_flood_incomplete_ratio: float = 0.8
    dns_entropy_threshold: float = 3.5
    dns_length_threshold: int = 50
    arp_max_ips_per_mac: int = 3
