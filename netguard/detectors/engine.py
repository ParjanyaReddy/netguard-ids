from typing import List, Dict, Optional
from netguard.detectors.base import BaseDetector
from netguard.detectors.port_scan import PortScanDetector
from netguard.detectors.syn_flood import SynFloodDetector
from netguard.detectors.dns_tunnel import DnsTunnelDetector
from netguard.detectors.arp_spoof import ArpSpoofDetector
from netguard.parser.decode import PacketEvent
from netguard.alerts.models import Alert


class DetectionEngine:
    """
    Coordinates and executes all configured detection modules against incoming network events.
    """
    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        if detectors is None:
            # Default suite of built-in detectors
            self.detectors: Dict[str, BaseDetector] = {
                "port_scan": PortScanDetector(),
                "syn_flood": SynFloodDetector(),
                "dns_tunnel": DnsTunnelDetector(),
                "arp_spoof": ArpSpoofDetector(),
            }
        else:
            self.detectors = {d.name: d for d in detectors}

    def register(self, detector: BaseDetector) -> None:
        self.detectors[detector.name] = detector

    def get_detector(self, name: str) -> Optional[BaseDetector]:
        return self.detectors.get(name)

    def process(self, event: PacketEvent) -> List[Alert]:
        alerts: List[Alert] = []
        for detector in self.detectors.values():
            if detector.enabled:
                detected = detector.process(event)
                if detected:
                    alerts.extend(detected)
        return alerts

    def reset_all(self) -> None:
        for detector in self.detectors.values():
            detector.reset()
