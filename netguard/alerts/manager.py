from typing import Dict, Tuple, Optional, List
from netguard.alerts.models import Alert


class AlertManager:
    """
    Manages incoming alerts, suppressing duplicates within a cooldown window
    to prevent alert fatigue and system saturation.
    """
    def __init__(self, cooldown_seconds: float = 60.0):
        self.cooldown_seconds = cooldown_seconds
        # (alert_type, src, dst) -> last_seen_timestamp
        self._last_alert_time: Dict[Tuple[str, Optional[str], Optional[str]], float] = {}
        # (alert_type, src, dst) -> suppressed count
        self._suppressed_counts: Dict[Tuple[str, Optional[str], Optional[str]], int] = {}

    def should_emit(self, alert: Alert) -> bool:
        key = (alert.alert_type, alert.src, alert.dst)
        last_time = self._last_alert_time.get(key)

        if last_time is None or (alert.ts - last_time) >= self.cooldown_seconds:
            self._last_alert_time[key] = alert.ts
            suppressed = self._suppressed_counts.pop(key, 0)
            if suppressed > 0:
                alert.evidence["suppressed_repeats_during_cooldown"] = suppressed
            return True

        self._suppressed_counts[key] = self._suppressed_counts.get(key, 0) + 1
        return False

    def process(self, alerts: List[Alert]) -> List[Alert]:
        return [alert for alert in alerts if self.should_emit(alert)]

    def reset(self) -> None:
        self._last_alert_time.clear()
        self._suppressed_counts.clear()
