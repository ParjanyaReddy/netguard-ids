import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw
from netguard.parser.decode import decode


def test_decode_tcp_packet():
    pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "TCP"
    assert ev.src == "192.168.1.100"
    assert ev.dst == "10.0.0.1"
    assert ev.sport == 12345
    assert ev.dport == 80
    assert "S" in ev.flags


def test_decode_udp_dns_packet():
    pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.example.com", qtype=16))
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "UDP"
    assert ev.src == "192.168.1.100"
    assert ev.dst == "8.8.8.8"
    assert ev.sport == 54321
    assert ev.dport == 53
    assert ev.dns_qname == "www.example.com"
    assert ev.dns_qtype == 16


def test_decode_arp_reply_packet():
    pkt = Ether() / ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.100", hwsrc="00:11:22:33:44:55", hwdst="aa:bb:cc:dd:ee:ff")
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "ARP"
    assert ev.arp_op == 2
    assert ev.arp_psrc == "192.168.1.1"
    assert ev.arp_hwsrc == "00:11:22:33:44:55"
    assert ev.src == "192.168.1.1"


def test_decode_ipv6_packet():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=443, flags="SA")
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "TCP"
    assert ev.src == "2001:db8::1"
    assert ev.dst == "2001:db8::2"
    assert ev.sport == 50000
    assert ev.dport == 443


def test_decode_icmp_packet():
    pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP()
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "ICMP"
    assert ev.src == "10.0.0.2"
    assert ev.dst == "10.0.0.1"


def test_decode_http_payload():
    payload = b"GET /api/v1/health HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4000, dport=80, flags="PA") / Raw(load=payload)
    ev = decode(pkt)
    assert ev is not None
    assert ev.http_method == "GET"
    assert ev.http_uri == "/api/v1/health"


def test_decode_malformed_packet_resilience():
    # An empty or malformed non-Ether/IP frame should return None safely without raising
    pkt = Ether()
    ev = decode(pkt)
    assert ev is None
