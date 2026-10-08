from collections import defaultdict, deque
from typing import List, Dict, Tuple, Optional, Set
from netguard.detectors.base import BaseDetector
from netguard.parser.decode import PacketEvent
from netguard.alerts.models import Alert
from netguard.flow.count_min_sketch import CountMinSketch


class PortScanDetector(BaseDetector):
    """
    Detects network reconnaissance (vertical port scans, horizontal sweeps, and
    low-and-slow evasion attacks) using sliding window aggregation, Count-Min Sketch (CMS)
    frequency estimation, and Exponentially Weighted Moving Average (EWMA) rate tracking.
    """
    def __init__(
        self,
        window_seconds: float = 10.0,
        threshold: int = 15,
        enable_ewma: bool = False,
        slow_scan_threshold: int = 20,
        slow_scan_window: float = 300.0,
        ewma_alpha: float = 0.2,
        name: str = "port_scan"
    ):
        super().__init__(name=name)
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.enable_ewma = enable_ewma
        self.slow_scan_threshold = slow_scan_threshold
        self.slow_scan_window = slow_scan_window
        self.ewma_alpha = ewma_alpha

        # Fast sliding window: src_ip -> deque of (timestamp, dst_ip, dport)
        self.history: Dict[str, deque] = defaultdict(deque)

        # Count-Min Sketch for strictly bounded-memory frequency tracking (Spec §3.3.2)
        # Guarantees constant memory (< 35 KB) regardless of stream cardinality
        self.cms = CountMinSketch(width=2048, depth=4, conservative_update=True)

        # EWMA state for low-and-slow reconnaissance tracking (Spec §5.3.1)
        # src_ip -> dict of {last_ts, first_ts, ewma_rate, targets: set}
        self.ewma_state: Dict[str, Dict] = {}

    def process(self, event: PacketEvent) -> List[Alert]:
        if not self.enabled:
            return []

        # Focus on TCP SYN attempts (pure SYN)
        if event.proto != "TCP" or not event.flags or "S" not in event.flags or "A" in event.flags:
            return []

        if not event.src or not event.dst or event.dport is None:
            return []

        src = event.src
        dst = event.dst
        dport = event.dport
        ts = event.ts

        # 1. Update Count-Min Sketch (CMS-CU)
        target_endpoint_key = f"{src}->{dst}:{dport}"
        src_scan_key = f"scan:{src}"
        self.cms.add(target_endpoint_key)
        self.cms.add(src_scan_key)

        alerts: List[Alert] = []

        # 2. Fast Sliding Window Detection (Vertical / Horizontal Scans)
        q = self.history[src]
        q.append((ts, dst, dport))

        cutoff = ts - self.window_seconds
        while q and q[0][0] < cutoff:
            q.popleft()

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

            alerts.append(
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
                        "cms_estimated_volume": self.cms.estimate(src_scan_key),
                    },
                    ts=ts
                )
            )
            return alerts

        # 3. EWMA Low-and-Slow Evasion Detection (Spec §5.3.1)
        if self.enable_ewma:
            low_slow_alert = self._process_ewma(src, dst, dport, ts, src_scan_key)
            if low_slow_alert:
                alerts.append(low_slow_alert)

        return alerts

    def _process_ewma(self, src: str, dst: str, dport: int, ts: float, src_scan_key: str) -> Optional[Alert]:
        """
        Calculates Exponentially Weighted Moving Average rate to catch stealthy
        reconnaissance spaced out beyond the standard sliding window.
        """
        if src not in self.ewma_state:
            self.ewma_state[src] = {
                "first_ts": ts,
                "last_ts": ts,
                "ewma_rate": 1.0,
                "probed_endpoints": {(dst, dport)},
            }
            return None

        state = self.ewma_state[src]
        dt = max(0.001, ts - state["last_ts"])
        instantaneous_rate = 1.0 / dt

        # EWMA update: EWMA_t = alpha * Rate_current + (1 - alpha) * EWMA_{t-1}
        state["ewma_rate"] = (self.ewma_alpha * instantaneous_rate) + ((1.0 - self.ewma_alpha) * state["ewma_rate"])
        state["last_ts"] = ts
        state["probed_endpoints"].add((dst, dport))

        elapsed = ts - state["first_ts"]

        # If scan exceeded the short window and accumulated enough targets over time
        if elapsed > self.window_seconds and len(state["probed_endpoints"]) >= self.slow_scan_threshold:
            unique_count = len(state["probed_endpoints"])
            rate = state["ewma_rate"]

            # Reset EWMA state for source to prevent alert storm
            del self.ewma_state[src]

            return Alert(
                alert_type="port_scan",
                severity="medium",
                src=src,
                dst=None,
                description=f"Low-and-slow stealth port scan detected from {src}: {unique_count} distinct endpoints probed across {round(elapsed, 1)}s (EWMA rate: {rate:.2f} pkts/s)",
                evidence={
                    "scan_type": "low_and_slow",
                    "unique_targets": unique_count,
                    "elapsed_seconds": round(elapsed, 1),
                    "ewma_rate": round(rate, 4),
                    "cms_estimated_volume": self.cms.estimate(src_scan_key),
                },
                ts=ts
            )

        # Evict state if dormant beyond slow_scan_window
        if elapsed > self.slow_scan_window:
            del self.ewma_state[src]

        return None

    def reset(self) -> None:
        self.history.clear()
        self.cms.clear()
        self.ewma_state.clear()
