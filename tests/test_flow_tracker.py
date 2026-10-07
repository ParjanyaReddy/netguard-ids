import pytest
from netguard.parser.decode import PacketEvent
from netguard.flow.tracker import FlowTracker, canonical_flow_key


def test_canonical_flow_key_bidirectional():
    key1 = canonical_flow_key("192.168.1.10", "10.0.0.1", 54321, 80, "TCP")
    key2 = canonical_flow_key("10.0.0.1", "192.168.1.10", 80, 54321, "TCP")
    assert key1 == key2


def test_canonical_flow_key_portless():
    key1 = canonical_flow_key("192.168.1.10", "10.0.0.1", None, None, "ICMP")
    key2 = canonical_flow_key("10.0.0.1", "192.168.1.10", None, None, "ICMP")
    assert key1 == key2


def test_flow_packet_and_byte_counters():
    tracker = FlowTracker()
    
    # Forward packet
    p1 = PacketEvent(ts=100.0, src="192.168.1.5", dst="10.0.0.1", proto="TCP", sport=1000, dport=80, flags="S", size=60)
    flow = tracker.process(p1)
    
    assert tracker.active_flows_count() == 1
    assert flow.packets_forward == 1
    assert flow.bytes_forward == 60
    assert flow.packets_reverse == 0
    assert flow.bytes_reverse == 0
    assert flow.total_packets == 1
    assert flow.total_bytes == 60

    # Reverse packet
    p2 = PacketEvent(ts=100.1, src="10.0.0.1", dst="192.168.1.5", proto="TCP", sport=80, dport=1000, flags="SA", size=60)
    flow2 = tracker.process(p2)
    
    assert flow2 is flow
    assert tracker.active_flows_count() == 1
    assert flow.packets_forward == 1
    assert flow.packets_reverse == 1
    assert flow.total_packets == 2
    assert flow.total_bytes == 120
    assert flow.duration == pytest.approx(0.1)


def test_tcp_state_machine_handshake_and_close():
    tracker = FlowTracker()
    
    # 1. SYN
    syn = PacketEvent(ts=1.0, src="192.168.1.5", dst="10.0.0.1", proto="TCP", sport=2000, dport=80, flags="S", size=60)
    f = tracker.process(syn)
    assert f.tcp_state == "SYN_SENT"

    # 2. SYN-ACK
    syn_ack = PacketEvent(ts=1.1, src="10.0.0.1", dst="192.168.1.5", proto="TCP", sport=80, dport=2000, flags="SA", size=60)
    f = tracker.process(syn_ack)
    assert f.tcp_state == "SYN_RECEIVED"

    # 3. ACK
    ack = PacketEvent(ts=1.2, src="192.168.1.5", dst="10.0.0.1", proto="TCP", sport=2000, dport=80, flags="A", size=52)
    f = tracker.process(ack)
    assert f.tcp_state == "ESTABLISHED"

    # 4. FIN from client
    fin1 = PacketEvent(ts=1.5, src="192.168.1.5", dst="10.0.0.1", proto="TCP", sport=2000, dport=80, flags="FA", size=52)
    f = tracker.process(fin1)
    assert f.tcp_state == "FIN_WAIT"

    # 5. FIN from server
    fin2 = PacketEvent(ts=1.6, src="10.0.0.1", dst="192.168.1.5", proto="TCP", sport=80, dport=2000, flags="FA", size=52)
    f = tracker.process(fin2)
    assert f.tcp_state == "CLOSED"


def test_tcp_midstream_connection():
    tracker = FlowTracker()
    # Packet arrives with ACK without seeing initial SYN
    data_pkt = PacketEvent(ts=50.0, src="192.168.1.10", dst="10.0.0.1", proto="TCP", sport=4567, dport=443, flags="PA", size=200)
    flow = tracker.process(data_pkt)
    assert flow.tcp_state == "ESTABLISHED"


def test_tcp_reset_handling():
    tracker = FlowTracker()
    syn = PacketEvent(ts=1.0, src="192.168.1.5", dst="10.0.0.1", proto="TCP", sport=2001, dport=80, flags="S", size=60)
    tracker.process(syn)

    rst = PacketEvent(ts=1.1, src="10.0.0.1", dst="192.168.1.5", proto="TCP", sport=80, dport=2001, flags="R", size=40)
    f = tracker.process(rst)
    assert f.tcp_state == "RESET"


def test_icmp_flow_tracking():
    tracker = FlowTracker()
    ping_req = PacketEvent(ts=10.0, src="10.0.0.5", dst="10.0.0.1", proto="ICMP", size=84)
    flow = tracker.process(ping_req)
    assert flow.proto == "ICMP"
    assert flow.packets_forward == 1
    assert flow.packets_reverse == 0

    ping_reply = PacketEvent(ts=10.02, src="10.0.0.1", dst="10.0.0.5", proto="ICMP", size=84)
    flow2 = tracker.process(ping_reply)
    assert flow2 is flow
    assert flow.packets_forward == 1
    assert flow.packets_reverse == 1
    assert flow.total_packets == 2


def test_flow_idle_eviction():
    tracker = FlowTracker(default_idle_timeout=10.0, tcp_established_timeout=20.0)
    
    # Short-lived UDP flow at ts=0.0
    udp_pkt = PacketEvent(ts=0.0, src="192.168.1.10", dst="8.8.8.8", proto="UDP", sport=5000, dport=53, size=70)
    tracker.process(udp_pkt)

    # Active TCP flow at ts=5.0
    syn_pkt = PacketEvent(ts=5.0, src="192.168.1.20", dst="1.1.1.1", proto="TCP", sport=6000, dport=443, flags="S", size=60)
    tracker.process(syn_pkt)

    assert tracker.active_flows_count() == 2

    # At ts=12.0: UDP (idle 12s > 10s) should evict, TCP (idle 7s < 10s) stays
    evicted = tracker.evict_idle(current_ts=12.0)
    assert len(evicted) == 1
    assert evicted[0].proto == "UDP"
    assert tracker.active_flows_count() == 1

    # At ts=25.0: Remaining flow (idle 20s > 10s) should evict
    evicted_remaining = tracker.evict_idle(current_ts=25.0)
    assert len(evicted_remaining) == 1
    assert tracker.active_flows_count() == 0
