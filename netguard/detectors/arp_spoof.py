from collections import defaultdict
from typing import List, Dict, Set, Optional
from netguard.detectors.base import BaseDetector
from netguard.parser.decode import PacketEvent
from netguard.alerts.models import Alert


class ArpSpoofDetector(BaseDetector):
    def __init__(self, gateway_ip: Optional[str] = None, max_ips_per_mac: int = 3, name: str = "arp_spoof"):
        super().__init__(name=name)
        self.gateway_ip = gateway_ip
        self.max_ips_per_mac = max_ips_per_mac

        # Known mapping: IP -> MAC
        self.ip_to_mac: Dict[str, str] = {}
        # Known mapping: MAC -> Set of claimed IPs
        self.mac_to_ips: Dict[str, Set[str]] = defaultdict(set)

    def process(self, event: PacketEvent) -> List[Alert]:
        if not self.enabled or event.proto != "ARP":
            return []

        ip = event.arp_psrc or event.src
        mac = (event.arp_hwsrc or event.flags or "").lower()

        if not ip or not mac or mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
            return []

        alerts: List[Alert] = []

        # Check 1: IP address MAC mismatch (ARP Poisoning / Spoofing)
        if ip in self.ip_to_mac:
            existing_mac = self.ip_to_mac[ip]
            if existing_mac != mac:
                is_gateway = (self.gateway_ip and ip == self.gateway_ip)
                alerts.append(
                    Alert(
                        alert_type="arp_spoof",
                        severity="critical" if is_gateway else "high",
                        src=ip,
                        dst=event.dst,
                        description=f"ARP cache poisoning detected: IP {ip} claimed by MAC {mac} (previously mapped to {existing_mac})"
                        + (" [TARGET IS DEFAULT GATEWAY]" if is_gateway else ""),
                        evidence={
                            "ip": ip,
                            "original_mac": existing_mac,
                            "spoofed_mac": mac,
                            "is_gateway": bool(is_gateway),
                            "arp_op": event.arp_op,
                        },
                        ts=event.ts
                    )
                )
                # Update mapping to the new MAC to avoid repeating identical alerts indefinitely
                self.mac_to_ips[existing_mac].discard(ip)
                self.ip_to_mac[ip] = mac
                self.mac_to_ips[mac].add(ip)
                return alerts
        else:
            self.ip_to_mac[ip] = mac
            self.mac_to_ips[mac].add(ip)

        # Check 2: Single MAC claiming an abnormal number of distinct IPs
        claimed_ips = self.mac_to_ips[mac]
        if len(claimed_ips) > self.max_ips_per_mac:
            alerts.append(
                Alert(
                    alert_type="arp_spoof",
                    severity="high",
                    src=ip,
                    dst=None,
                    description=f"Potential ARP MITM attack: MAC {mac} claims {len(claimed_ips)} distinct IPs",
                    evidence={
                        "mac": mac,
                        "claimed_ips": sorted(list(claimed_ips)),
                        "threshold": self.max_ips_per_mac,
                    },
                    ts=event.ts
                )
            )

        return alerts

    def reset(self) -> None:
        self.ip_to_mac.clear()
        self.mac_to_ips.clear()
