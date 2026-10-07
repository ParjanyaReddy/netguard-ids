from abc import ABC, abstractmethod
from typing import List
from netguard.parser.decode import PacketEvent
from netguard.alerts.models import Alert


class BaseDetector(ABC):
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def process(self, event: PacketEvent) -> List[Alert]:
        """
        Inspects an incoming PacketEvent and returns a list of fired Alerts.
        """
        pass

    def reset(self) -> None:
        """
        Resets any transient state held by the detector.
        """
        pass
