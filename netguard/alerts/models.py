from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import uuid
import time


@dataclass
class Alert:
    alert_type: str
    severity: str  # "low", "medium", "high", "critical"
    src: Optional[str]
    dst: Optional[str]
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
