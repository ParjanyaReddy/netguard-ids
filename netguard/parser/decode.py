from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw
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
    dns_qtype: Optional[int] = None
    arp_op: Optional[int] = None
    arp_hwsrc: Optional[str] = None
    arp_psrc: Optional[str] = None
    arp_hwdst: Optional[str] = None
    arp_pdst: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    size: int = 0


def decode(pkt) -> Optional[PacketEvent]:
    """
    Safely dissects raw network frames across layers L2-L7 into a normalized PacketEvent.
    Handles malformed or truncated packets without throwing exceptions.
    """
    try:
        ts = float(getattr(pkt, "time", 0.0))
        # Safely determine packet length without triggering Scapy route resolution
        pkt_len = getattr(pkt, "wirelen", None)
        if pkt_len is None:
            try:
                pkt_len = len(pkt)
            except Exception:
                pkt_len = 0

        # Layer 2: ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            return PacketEvent(
                ts=ts,
                src=arp.psrc,
                dst=arp.pdst,
                proto="ARP",
                flags=str(arp.hwsrc),
                arp_op=int(arp.op),
                arp_hwsrc=str(arp.hwsrc),
                arp_psrc=str(arp.psrc),
                arp_hwdst=str(arp.hwdst),
                arp_pdst=str(arp.pdst),
                size=pkt_len
            )

        # Layer 3: IPv4 or IPv6
        src_ip = None
        dst_ip = None
        proto = "IP"

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto = "IPv6"
        else:
            # Non-IP and non-ARP frame
            return None

        ev = PacketEvent(
            ts=ts,
            src=src_ip,
            dst=dst_ip,
            proto=proto,
            size=pkt_len
        )

        # Layer 4: Transport Protocols
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            ev.proto = "TCP"
            ev.sport = tcp.sport
            ev.dport = tcp.dport
            ev.flags = str(tcp.flags)

            # Basic HTTP inspection on plain HTTP ports or payloads
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS "):
                    if payload.startswith(method):
                        try:
                            parts = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore").split(" ")
                            if len(parts) >= 2:
                                ev.http_method = parts[0]
                                ev.http_uri = parts[1]
                        except Exception:
                            pass
                        break

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            ev.proto = "UDP"
            ev.sport = udp.sport
            ev.dport = udp.dport

            # DNS dissection
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    dnsqr = pkt[DNSQR]
                    qname = dnsqr.qname
                    if isinstance(qname, bytes):
                        ev.dns_qname = qname.decode(errors="ignore").rstrip(".")
                    elif qname:
                        ev.dns_qname = str(qname).rstrip(".")
                    ev.dns_qtype = getattr(dnsqr, "qtype", None)
                except Exception:
                    pass

        elif pkt.haslayer(ICMP):
            ev.proto = "ICMP"

        return ev

    except Exception:
        # Prevent corrupted, fragmented or malformed packets from crashing capture
        return None
