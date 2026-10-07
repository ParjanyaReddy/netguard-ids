import threading
import queue
from scapy.all import sniff
from typing import Callable, Optional
from netguard.parser.decode import decode, PacketEvent

class LiveCapture:
    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "tcp or udp or arp", max_queue_size: int = 10000):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.event_queue = queue.Queue(maxsize=max_queue_size)
        self.dropped_packets = 0
        self._stop_event = threading.Event()
        self.capture_thread = None

    def _packet_handler(self, pkt):
        ev = decode(pkt)
        if ev:
            try:
                self.event_queue.put_nowait(ev)
            except queue.Full:
                self.dropped_packets += 1

    def start(self):
        self._stop_event.clear()
        
        def run_sniff():
            # stop_filter returns True to stop sniffing
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set()
            )
            
        self.capture_thread = threading.Thread(target=run_sniff, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self._stop_event.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            
    def get_event(self, timeout=1.0) -> Optional[PacketEvent]:
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None
