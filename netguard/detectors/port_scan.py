from collections import defaultdict, deque
from typing import List, Dict, Tuple, Optional
from netguard.detectors.base import BaseDetector
from netguard.parser.decode import PacketEvent
from netguard.alerts.models import Alert


class PortScanDetector(BaseDetector):
    def __init__(self, window_seconds: float = 10.0, threshold: int = 15, name: str = "port_scan"):
        super().__init__(name=name)
        self.window_seconds = window_seconds
        self.threshold = threshold
        # src_ip -> deque of (timestamp, dst_ip, dport)
        self.history: Dict[str, deque] = defaultdict(deque)

    def process(self, event: PacketEvent) -> List[Alert]:
        if not self.enabled:
            return []

        # Focus on TCP SYN attempts (pure SYN)
        if event.proto != "TCP" or not event.flags or "S" not in event.flags or "A" in event.flags:
            return []

        if not event.src or not event.dst or event.dport is None:
            return []

        src = event.src
        q = self.history[src]
        q.append((event.ts, event.dst, event.dport))

        # Evict timestamps outside sliding window
        cutoff = event.ts - self.window_seconds
        while q and q[0][0] < cutoff:
            q.popleft()

        # Count distinct target endpoints (dst, dport)
        targets = {(d, p) for _, d, p in q}
        if len(targets) >= self.threshold:
            dst_hosts = {d for d, _ in targets}
            dst_ports = {p for _, p in targets}

            if len(dst_hosts) == 1 and len(dst_ports) > 1:
                scan_type = "vertical"
                desc = f"Vertical port scan detected from {src}: {len(dst_ports)} ports targeted on {next(iter(dst_hosts))} within {self.window_seconds}s"
            elif len(dst_hosts) > 1 and len(dst_ports) == 1:
                scan_type = "horizontal"
                desc = f"Horizontal port sweep detected from {src}: port {next(iter(dst_ports))} scanned across {len(dst_hosts)} hosts within {self.window_seconds}s"
            else:
                scan_type = "distributed/hybrid"
                desc = f"Port scan detected from {src}: {len(targets)} distinct endpoints targeted across {len(dst_hosts)} hosts within {self.window_seconds}s"

            # Clear queue to prevent flooding alerts for the same burst
            q.clear()

            return [
                Alert(
                    alert_type="port_scan",
                    severity="high" if len(targets) >= self.threshold * 2 else "medium",
                    src=src,
                    dst=next(iter(dst_hosts)) if len(dst_hosts) == 1 else None,
                    description=desc,
                    evidence={
                        "scan_type": scan_type,
                        "unique_targets": len(targets),
                        "unique_ports": len(dst_ports),
                        "unique_hosts": len(dst_hosts),
                        "window_seconds": self.window_seconds,
                    },
                    ts=event.ts
                )
            ]

        return []

    def reset(self) -> None:
        self.history.clear()
