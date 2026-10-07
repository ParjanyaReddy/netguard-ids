from collections import defaultdict, deque
from typing import List, Dict, Tuple, Optional
from netguard.detectors.base import BaseDetector
from netguard.parser.decode import PacketEvent
from netguard.alerts.models import Alert


class SynFloodDetector(BaseDetector):
    def __init__(self, window_seconds: float = 5.0, threshold_syn_count: int = 40, incomplete_ratio_threshold: float = 0.8, name: str = "syn_flood"):
        super().__init__(name=name)
        self.window_seconds = window_seconds
        self.threshold_syn_count = threshold_syn_count
        self.incomplete_ratio_threshold = incomplete_ratio_threshold

        # dst_ip -> deque of (timestamp, 5_tuple_or_flow_id) for pure SYNs
        self.syn_events: Dict[str, deque] = defaultdict(deque)
        # flow_key -> timestamp completed
        self.completed_flows: Dict[Tuple, float] = {}

    def process(self, event: PacketEvent) -> List[Alert]:
        if not self.enabled or event.proto != "TCP" or not event.flags:
            return []

        flags = event.flags

        # Completed handshake or response ACK
        if "A" in flags and event.src and event.dst and event.sport and event.dport:
            flow_key = tuple(sorted([(event.src, event.sport), (event.dst, event.dport)]))
            self.completed_flows[flow_key] = event.ts

        # Monitor incoming pure SYN packets
        if "S" in flags and "A" not in flags and event.dst and event.src and event.sport and event.dport:
            target_ip = event.dst
            flow_key = tuple(sorted([(event.src, event.sport), (event.dst, event.dport)]))

            q = self.syn_events[target_ip]
            q.append((event.ts, flow_key, event.src))

            # Evict timestamps outside window
            cutoff = event.ts - self.window_seconds
            while q and q[0][0] < cutoff:
                q.popleft()

            # Clean expired completed flows
            to_remove = [k for k, t in self.completed_flows.items() if t < cutoff]
            for k in to_remove:
                del self.completed_flows[k]

            if len(q) >= self.threshold_syn_count:
                # Calculate incomplete ratio
                incomplete_count = sum(1 for _, fk, _ in q if fk not in self.completed_flows)
                ratio = incomplete_count / len(q)

                if ratio >= self.incomplete_ratio_threshold:
                    sources = {s for _, _, s in q}
                    q.clear()  # Clear window after detection to prevent alert flood

                    return [
                        Alert(
                            alert_type="syn_flood",
                            severity="critical",
                            src=None if len(sources) > 1 else next(iter(sources)),
                            dst=target_ip,
                            description=f"SYN flood detected against {target_ip}: {incomplete_count}/{len(q) + incomplete_count} half-open SYNs from {len(sources)} source(s) in {self.window_seconds}s",
                            evidence={
                                "syn_count": len(q) + incomplete_count,
                                "half_open_count": incomplete_count,
                                "incomplete_ratio": round(ratio, 2),
                                "unique_attackers": len(sources),
                                "target_ip": target_ip,
                                "window_seconds": self.window_seconds,
                            },
                            ts=event.ts
                        )
                    ]

        return []

    def reset(self) -> None:
        self.syn_events.clear()
        self.completed_flows.clear()
