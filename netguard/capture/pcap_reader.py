import queue
from typing import Optional
from scapy.all import PcapReader
from netguard.parser.decode import decode, PacketEvent

class PcapFileCapture:
    def __init__(self, pcap_path: str, max_queue_size: int = 10000):
        self.pcap_path = pcap_path
        self.event_queue = queue.Queue(maxsize=max_queue_size)
        self.dropped_packets = 0

    def process(self):
        """Reads the entire pcap file and populates the queue."""
        with PcapReader(self.pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                ev = decode(pkt)
                if ev:
                    try:
                        self.event_queue.put_nowait(ev)
                    except queue.Full:
                        self.dropped_packets += 1

    def get_event(self, timeout=1.0) -> Optional[PacketEvent]:
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None
