from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, List
from netguard.parser.decode import PacketEvent


def canonical_flow_key(src: Optional[str], dst: Optional[str], sport: Optional[int], dport: Optional[int], proto: str) -> Tuple:
    """
    Normalizes a 5-tuple so packets travelling in either direction map to the same key.
    """
    ep1 = (src or "", sport or 0)
    ep2 = (dst or "", dport or 0)
    if ep1 <= ep2:
        return (ep1, ep2, proto)
    return (ep2, ep1, proto)


@dataclass
class Flow:
    key: Tuple
    proto: str
    initiator_ip: Optional[str]
    initiator_port: Optional[int]
    responder_ip: Optional[str]
    responder_port: Optional[int]
    start_ts: float
    last_seen_ts: float
    packets_forward: int = 0
    bytes_forward: int = 0
    packets_reverse: int = 0
    bytes_reverse: int = 0
    tcp_state: str = "NONE"
    fin_forward: bool = False
    fin_reverse: bool = False

    @property
    def total_packets(self) -> int:
        return self.packets_forward + self.packets_reverse

    @property
    def total_bytes(self) -> int:
        return self.bytes_forward + self.bytes_reverse

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen_ts - self.start_ts)

    def is_forward(self, ev: PacketEvent) -> bool:
        return ev.src == self.initiator_ip and (ev.sport == self.initiator_port or self.initiator_port == 0)

    def update(self, ev: PacketEvent) -> None:
        self.last_seen_ts = max(self.last_seen_ts, ev.ts)
        forward = self.is_forward(ev)

        if forward:
            self.packets_forward += 1
            self.bytes_forward += ev.size
        else:
            self.packets_reverse += 1
            self.bytes_reverse += ev.size

        if self.proto == "TCP" and ev.flags:
            self._update_tcp_state(ev.flags, forward)

    def _update_tcp_state(self, flags: str, forward: bool) -> None:
        # Reset flag immediately closes flow
        if "R" in flags:
            self.tcp_state = "RESET"
            return

        # Check FIN flags
        if "F" in flags:
            if forward:
                self.fin_forward = True
            else:
                self.fin_reverse = True

            if self.fin_forward and self.fin_reverse:
                self.tcp_state = "CLOSED"
            else:
                self.tcp_state = "FIN_WAIT"
            return

        # Handshake transitions
        if self.tcp_state == "NONE":
            if "S" in flags and "A" not in flags:
                self.tcp_state = "SYN_SENT"
        elif self.tcp_state == "SYN_SENT":
            if "S" in flags and "A" in flags and not forward:
                self.tcp_state = "SYN_RECEIVED"
            elif "A" in flags and forward:
                self.tcp_state = "ESTABLISHED"
        elif self.tcp_state == "SYN_RECEIVED":
            if "A" in flags and forward:
                self.tcp_state = "ESTABLISHED"


class FlowTracker:
    def __init__(self, default_idle_timeout: float = 60.0, tcp_established_timeout: float = 300.0):
        self.default_idle_timeout = default_idle_timeout
        self.tcp_established_timeout = tcp_established_timeout
        self.flows: Dict[Tuple, Flow] = {}

    def process(self, ev: PacketEvent) -> Flow:
        key = canonical_flow_key(ev.src, ev.dst, ev.sport, ev.dport, ev.proto)
        flow = self.flows.get(key)

        if flow is None:
            flow = Flow(
                key=key,
                proto=ev.proto,
                initiator_ip=ev.src,
                initiator_port=ev.sport,
                responder_ip=ev.dst,
                responder_port=ev.dport,
                start_ts=ev.ts,
                last_seen_ts=ev.ts
            )
            self.flows[key] = flow

        flow.update(ev)
        return flow

    def evict_idle(self, current_ts: float) -> List[Flow]:
        """
        Removes flows that have exceeded their idle timeout threshold and returns them.
        """
        evicted = []
        keys_to_remove = []

        for key, flow in self.flows.items():
            timeout = self.tcp_established_timeout if flow.tcp_state == "ESTABLISHED" else self.default_idle_timeout
            if current_ts - flow.last_seen_ts > timeout:
                keys_to_remove.append(key)
                evicted.append(flow)

        for key in keys_to_remove:
            del self.flows[key]

        return evicted

    def active_flows_count(self) -> int:
        return len(self.flows)
