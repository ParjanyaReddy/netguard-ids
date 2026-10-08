import os
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, ARP, wrpcap


def generate_all_pcaps(output_dir: str = "tests/pcaps"):
    """
    Generates small, reproducible, labeled .pcap fixtures for testing the IDS.
    """
    os.makedirs(output_dir, exist_ok=True)

    # 1. Benign Traffic PCAP
    benign_pkts = []
    base_ts = 100.0
    for i in range(10):
        ts = base_ts + (i * 0.2)
        # HTTP 3-way handshake
        sport = 50000 + i
        syn = Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:02") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=sport, dport=80, flags="S")
        syn.time = ts
        syn_ack = Ether(src="00:11:22:33:44:02", dst="00:11:22:33:44:01") / IP(src="192.168.1.1", dst="192.168.1.50") / TCP(sport=80, dport=sport, flags="SA")
        syn_ack.time = ts + 0.01
        ack = Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:02") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=sport, dport=80, flags="A")
        ack.time = ts + 0.02
        benign_pkts.extend([syn, syn_ack, ack])

        # Normal DNS
        dns_pkt = Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:02") / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname="www.wikipedia.org", qtype=1))
        dns_pkt.time = ts + 0.05
        benign_pkts.append(dns_pkt)

    wrpcap(os.path.join(output_dir, "benign_traffic.pcap"), benign_pkts)

    # 2. Port Scan PCAP (Vertical SYN scan: 25 ports on victim)
    scan_pkts = []
    scan_ts = 200.0
    for i in range(25):
        pkt = Ether(src="00:aa:bb:cc:dd:01", dst="00:11:22:33:44:02") / IP(src="10.0.0.99", dst="192.168.1.10") / TCP(sport=40000 + i, dport=1000 + i, flags="S")
        pkt.time = scan_ts + (i * 0.05)
        scan_pkts.append(pkt)
    wrpcap(os.path.join(output_dir, "port_scan.pcap"), scan_pkts)

    # 3. SYN Flood PCAP (50 unacknowledged SYNs against target port 80)
    flood_pkts = []
    flood_ts = 300.0
    for i in range(50):
        src_ip = f"172.16.1.{10 + (i % 20)}"
        pkt = Ether(src="00:de:ad:be:ef:01", dst="00:11:22:33:44:02") / IP(src=src_ip, dst="192.168.1.10") / TCP(sport=20000 + i, dport=80, flags="S")
        pkt.time = flood_ts + (i * 0.02)
        flood_pkts.append(pkt)
    wrpcap(os.path.join(output_dir, "syn_flood.pcap"), flood_pkts)

    # 4. DNS Tunnel PCAP (High-entropy TXT exfiltration)
    dns_pkts = []
    dns_ts = 400.0
    chunks = [
        "7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
        "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
        "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
        "11223344556677889900aabbccddeeff",
        "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
        "f1e2d3c4b5a697887766554433221100",
        "deadbeefcafebabe0123456789abcdef",
        "0fedcba987654321deadbeefcafebabe",
        "a1b2c3d4e5f6789012345678abcdef01",
        "bbccddeeff00112233445566778899aa",
        "1234567890abcdef1234567890abcdef",
        "fedcba9876543210fedcba9876543210",
        "abcdef0123456789abcdef0123456789",
        "00112233445566778899aabbccddeeff",
        "5566778899aabbccddeeff0011223344",
        "99aabbccddeeff001122334455667788"
    ]
    for i, chunk in enumerate(chunks):
        qname = f"{chunk}.tunnel.c2server.org"
        pkt = Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:02") / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=51000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=16))
        pkt.time = dns_ts + (i * 0.1)
        dns_pkts.append(pkt)
    wrpcap(os.path.join(output_dir, "dns_tunnel.pcap"), dns_pkts)

    # 5. ARP Spoof PCAP (Legitimate gateway followed by rogue MAC claiming gateway IP)
    arp_pkts = []
    arp_ts = 500.0
    # Legitimate gateway reply
    legit_arp = Ether(src="00:50:56:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.50", hwsrc="00:50:56:00:00:01")
    legit_arp.time = arp_ts
    arp_pkts.append(legit_arp)

    # Rogue attacker poisons gateway IP
    rogue_arp = Ether(src="00:11:22:aa:bb:cc", dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.50", hwsrc="00:11:22:aa:bb:cc")
    rogue_arp.time = arp_ts + 0.5
    arp_pkts.append(rogue_arp)

    wrpcap(os.path.join(output_dir, "arp_spoof.pcap"), arp_pkts)
    print(f"Successfully generated 5 PCAP fixtures in {output_dir}")


if __name__ == "__main__":
    generate_all_pcaps()
