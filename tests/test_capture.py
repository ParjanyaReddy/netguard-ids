import queue
import time
import pytest
from scapy.all import Ether, IP, TCP, wrpcap
from netguard.capture.live import LiveCapture
from netguard.capture.pcap_reader import PcapFileCapture


def test_live_capture_packet_handler_and_drop_counter():
    # Set tiny queue to test drop backpressure
    cap = LiveCapture(max_queue_size=2)
    pkt1 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=100, dport=200)
    pkt2 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=101, dport=200)
    pkt3 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=102, dport=200)

    cap._packet_handler(pkt1)
    cap._packet_handler(pkt2)
    # Queue is now full (maxsize=2)
    cap._packet_handler(pkt3)

    assert cap.dropped_packets == 1
    assert cap.event_queue.qsize() == 2

    # Verify FIFO order
    ev1 = cap.get_event(timeout=0.1)
    assert ev1 is not None
    assert ev1.sport == 100

    ev2 = cap.get_event(timeout=0.1)
    assert ev2 is not None
    assert ev2.sport == 101

    # Now empty
    ev3 = cap.get_event(timeout=0.01)
    assert ev3 is None


def test_pcap_reader(tmp_path):
    pcap_file = tmp_path / "test.pcap"
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="SA"),
    ]
    wrpcap(str(pcap_file), packets)

    reader = PcapFileCapture(str(pcap_file))
    reader.process()

    assert reader.event_queue.qsize() == 2
    ev1 = reader.get_event(timeout=0.1)
    assert ev1 is not None
    assert ev1.src == "10.0.0.1"
    assert ev1.dport == 80

    ev2 = reader.get_event(timeout=0.1)
    assert ev2 is not None
    assert ev2.src == "10.0.0.2"
    assert ev2.sport == 80

    ev3 = reader.get_event(timeout=0.01)
    assert ev3 is None
