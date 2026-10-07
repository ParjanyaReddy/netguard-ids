import os
import sys
import time
import random
import string
from typing import List, Tuple

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, ARP, wrpcap
from netguard.parser.decode import decode, PacketEvent


def generate_benign_traffic(base_ts: float = 100.0, count: int = 50) -> List[Tuple[PacketEvent, str]]:
    """
    Generates standard browsing, DNS, and ICMP benign background traffic.
    """
    events = []
    mac_client = "00:11:22:33:44:01"
    mac_server = "00:11:22:33:44:02"

    ip_to_mac_map = {
        "172.28.0.50": "00:11:22:33:44:50",
        "172.28.0.55": "00:11:22:33:44:55",
        "172.28.0.60": "00:11:22:33:44:60",
        "172.28.0.65": "00:11:22:33:44:65",
        "172.28.0.70": "00:11:22:33:44:70",
        "172.28.0.75": "00:11:22:33:44:75",
        "172.28.0.80": "00:11:22:33:44:80",
        "172.28.0.85": "00:11:22:33:44:85",
    }
    client_ips = list(ip_to_mac_map.keys())

    for i in range(count):
        ts = base_ts + (i * 0.1)
        client_ip = random.choice(client_ips)
        mac_client = ip_to_mac_map[client_ip]
        choice = i % 3

        if choice == 0:
            # Normal HTTP session with dynamic payload transfer
            sport = 49152 + (i % 1000)
            syn = Ether(src=mac_client, dst=mac_server) / IP(src=client_ip, dst="172.28.0.10") / TCP(sport=sport, dport=80, flags="S")
            syn.time = ts
            events.append((decode(syn), "benign"))

            syn_ack = Ether(src=mac_server, dst=mac_client) / IP(src="172.28.0.10", dst=client_ip) / TCP(sport=80, dport=sport, flags="SA")
            syn_ack.time = ts + 0.01
            events.append((decode(syn_ack), "benign"))

            ack = Ether(src=mac_client, dst=mac_server) / IP(src=client_ip, dst="172.28.0.10") / TCP(sport=sport, dport=80, flags="A")
            ack.time = ts + 0.02
            events.append((decode(ack), "benign"))

            # Data payload packet
            data_size = random.randint(300, 4500)
            data_pkt = Ether(src=mac_client, dst=mac_server) / IP(src=client_ip, dst="172.28.0.10") / TCP(sport=sport, dport=80, flags="PA") / ("X" * data_size)
            data_pkt.time = ts + 0.03
            events.append((decode(data_pkt), "benign"))

        elif choice == 1:
            # Normal DNS query from diverse clients
            qnames = ["www.google.com", "api.github.com", "cdn.cloudflare.net", "news.ycombinator.com", "slack.com", "zoom.us"]
            qname = random.choice(qnames)
            dns_pkt = Ether(src=mac_client, dst=mac_server) / IP(src=client_ip, dst="8.8.8.8") / UDP(sport=53000 + (i % 5000), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=1))
            dns_pkt.time = ts
            events.append((decode(dns_pkt), "benign"))

        else:
            # Normal ARP lookup from diverse clients with their permanent MAC
            arp_pkt = Ether(src=mac_client, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=client_ip, pdst="172.28.0.1", hwsrc=mac_client)
            arp_pkt.time = ts
            events.append((decode(arp_pkt), "benign"))

    return [(ev, label) for ev, label in events if ev is not None]


def generate_port_scan_traffic(base_ts: float = 200.0, num_ports: int = 30) -> List[Tuple[PacketEvent, str]]:
    """
    Simulates vertical SYN port scan from attacker against victim.
    """
    events = []
    # Rotate between multiple external or internal compromised hosts
    attackers = ["172.28.0.20", "172.28.0.21", "172.28.0.22", "172.28.0.99"]
    attacker_ip = random.choice(attackers)
    victim_ip = "172.28.0.10"
    mac = "00:11:22:33:44:aa"

    for i in range(num_ports):
        port = 1000 + i
        pkt = Ether(src=mac, dst="00:11:22:33:44:bb") / IP(src=attacker_ip, dst=victim_ip) / TCP(sport=40000 + i, dport=port, flags="S")
        pkt.time = base_ts + (i * 0.05)
        events.append((decode(pkt), "port_scan"))

    return [(ev, label) for ev, label in events if ev is not None]


def generate_syn_flood_traffic(base_ts: float = 300.0, count: int = 60) -> List[Tuple[PacketEvent, str]]:
    """
    Simulates rapid unacknowledged SYN flood against target service.
    """
    events = []
    victim_ip = "172.28.0.10"

    for i in range(count):
        src_ip = f"172.28.{random.randint(1, 254)}.{random.randint(1, 254)}"
        pkt = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:bb") / IP(src=src_ip, dst=victim_ip) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        pkt.time = base_ts + (i * 0.02)
        events.append((decode(pkt), "syn_flood"))

    return [(ev, label) for ev, label in events if ev is not None]


def generate_dns_tunnel_traffic(base_ts: float = 400.0, count: int = 15) -> List[Tuple[PacketEvent, str]]:
    """
    Simulates DNS tunneling with high-entropy payload chunks in subdomains.
    """
    events = []
    tunnel_clients = ["172.28.0.20", "172.28.0.45", "172.28.0.88", "172.28.0.105"]
    attacker_ip = random.choice(tunnel_clients)

    for i in range(count):
        # Generate 32 characters of high-entropy hex data
        chunk = "".join(random.choices("0123456789abcdef", k=32))
        qname = f"{chunk}.exfil.attacker-c2.net"
        pkt = Ether(src="00:11:22:33:44:aa", dst="00:11:22:33:44:bb") / IP(src=attacker_ip, dst="8.8.8.8") / UDP(sport=50000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=16))
        pkt.time = base_ts + (i * 0.1)
        events.append((decode(pkt), "dns_tunnel"))

    return [(ev, label) for ev, label in events if ev is not None]


def generate_arp_spoof_traffic(base_ts: float = 500.0) -> List[Tuple[PacketEvent, str]]:
    """
    Simulates ARP cache poisoning against default gateway.
    """
    events = []
    legit_gw_mac = "aa:bb:cc:00:00:01"
    attacker_mac = "66:77:88:99:aa:bb"
    gateway_ip = "172.28.0.1"
    victim_ip = "172.28.0.10"

    # Legitimate gateway announcement first
    p1 = Ether(src=legit_gw_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=legit_gw_mac)
    p1.time = base_ts
    events.append((decode(p1), "benign"))

    # Attacker poisons gateway mapping
    for i in range(3):
        p_poison = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=attacker_mac)
        p_poison.time = base_ts + 2.0 + (i * 0.5)
        events.append((decode(p_poison), "arp_spoof"))

    return [(ev, label) for ev, label in events if ev is not None]


def generate_full_test_dataset() -> List[Tuple[PacketEvent, str]]:
    """
    Combines benign traffic and all 4 attack simulations into a labeled stream.
    """
    dataset = []
    dataset.extend(generate_benign_traffic(base_ts=100.0, count=60))
    dataset.extend(generate_port_scan_traffic(base_ts=200.0, num_ports=25))
    dataset.extend(generate_benign_traffic(base_ts=250.0, count=30))
    dataset.extend(generate_syn_flood_traffic(base_ts=300.0, count=50))
    dataset.extend(generate_benign_traffic(base_ts=350.0, count=30))
    dataset.extend(generate_dns_tunnel_traffic(base_ts=400.0, count=15))
    dataset.extend(generate_benign_traffic(base_ts=450.0, count=30))
    dataset.extend(generate_arp_spoof_traffic(base_ts=500.0))
    # Sort strictly by timestamp
    dataset.sort(key=lambda item: item[0].ts)
    return dataset
