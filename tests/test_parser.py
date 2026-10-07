import pytest
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, ARP
from netguard.parser.decode import decode

def test_decode_tcp_packet():
    pkt = Ether()/IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="S")
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "TCP"
    assert ev.src == "192.168.1.100"
    assert ev.dst == "10.0.0.1"
    assert ev.sport == 12345
    assert ev.dport == 80
    assert "S" in ev.flags

def test_decode_udp_dns_packet():
    pkt = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)/DNS(rd=1, qd=DNSQR(qname="www.example.com"))
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "UDP"
    assert ev.src == "192.168.1.100"
    assert ev.dst == "8.8.8.8"
    assert ev.sport == 54321
    assert ev.dport == 53
    assert ev.dns_qname == "www.example.com"

def test_decode_arp_packet():
    pkt = Ether()/ARP(psrc="192.168.1.1", pdst="192.168.1.100", hwsrc="00:11:22:33:44:55")
    ev = decode(pkt)
    assert ev is not None
    assert ev.proto == "ARP"
    assert ev.src == "192.168.1.1"
    assert ev.dst == "192.168.1.100"
    assert ev.flags == "00:11:22:33:44:55"
