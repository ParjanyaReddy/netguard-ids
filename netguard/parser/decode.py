from scapy.all import IP, TCP, UDP, DNS, DNSQR, ARP
from dataclasses import dataclass
from typing import Optional

@dataclass
class PacketEvent:
    ts: float
    src: Optional[str]
    dst: Optional[str]
    proto: str
    sport: Optional[int] = None
    dport: Optional[int] = None
    flags: Optional[str] = None
    dns_qname: Optional[str] = None
    size: int = 0

def decode(pkt) -> Optional[PacketEvent]:
    if ARP in pkt:
        return PacketEvent(
            ts=float(pkt.time),
            src=pkt[ARP].psrc,
            dst=pkt[ARP].pdst,
            proto="ARP",
            flags=str(pkt[ARP].hwsrc),
            size=len(pkt)
        )
    if IP not in pkt:
        return None
    
    ev = PacketEvent(
        ts=float(pkt.time),
        src=pkt[IP].src,
        dst=pkt[IP].dst,
        proto="IP",
        size=len(pkt)
    )
    
    if TCP in pkt:
        ev.proto = "TCP"
        ev.sport = pkt[TCP].sport
        ev.dport = pkt[TCP].dport
        ev.flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        ev.proto = "UDP"
        ev.sport = pkt[UDP].sport
        ev.dport = pkt[UDP].dport
        if DNS in pkt and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                ev.dns_qname = qname.decode(errors="ignore").rstrip(".")
            else:
                ev.dns_qname = str(qname).rstrip(".")
                
    return ev
