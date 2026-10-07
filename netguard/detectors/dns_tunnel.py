import math
from collections import Counter, defaultdict, deque
from typing import List, Dict, Tuple, Optional
from netguard.detectors.base import BaseDetector
from netguard.parser.decode import PacketEvent
from netguard.alerts.models import Alert


def shannon_entropy(s: str) -> float:
    """
    Computes Shannon entropy (bits per character) of a string.
    High entropy (> 3.5) typically denotes encrypted, compressed, or encoded data.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_domain_parts(qname: str) -> Tuple[str, str]:
    """
    Splits a FQDN into (subdomain, parent_domain).
    E.g., 'a1b2c3d4.tunnel.evil.com' -> ('a1b2c3d4', 'evil.com')
    """
    labels = qname.strip(".").split(".")
    if len(labels) <= 2:
        return ("", ".".join(labels))
    subdomain = ".".join(labels[:-2])
    parent_domain = ".".join(labels[-2:])
    return (subdomain, parent_domain)


class DnsTunnelDetector(BaseDetector):
    def __init__(
        self,
        entropy_threshold: float = 3.5,
        length_threshold: int = 50,
        subdomain_burst_threshold: int = 15,
        window_seconds: float = 15.0,
        score_threshold: int = 3,
        name: str = "dns_tunnel"
    ):
        super().__init__(name=name)
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.subdomain_burst_threshold = subdomain_burst_threshold
        self.window_seconds = window_seconds
        self.score_threshold = score_threshold

        # (src_ip, parent_domain) -> deque of (timestamp, subdomain)
        self.query_history: Dict[Tuple[str, str], deque] = defaultdict(deque)

    def process(self, event: PacketEvent) -> List[Alert]:
        if not self.enabled or not event.dns_qname or not event.src:
            return []

        qname = event.dns_qname.lower()
        subdomain, parent = extract_domain_parts(qname)
        src = event.src

        score = 0
        reasons = []

        # Signal 1: Abnormally long query name or subdomain label
        if len(qname) >= self.length_threshold:
            score += 1
            reasons.append(f"Long query name ({len(qname)} chars >= {self.length_threshold})")

        # Signal 2: High Shannon entropy in subdomain
        entropy = shannon_entropy(subdomain)
        if entropy >= self.entropy_threshold and len(subdomain) >= 10:
            score += 2
            reasons.append(f"High subdomain entropy ({round(entropy, 2)} >= {self.entropy_threshold})")

        # Signal 3: Unusual query record type (TXT = 16, NULL = 10 commonly abused for data exfil)
        if event.dns_qtype in (10, 16):
            score += 1
            reasons.append(f"High-capacity record type queried (qtype={event.dns_qtype})")

        # Signal 4: Rapid unique subdomains to the same parent domain
        if parent:
            key = (src, parent)
            q = self.query_history[key]
            q.append((event.ts, subdomain))

            cutoff = event.ts - self.window_seconds
            while q and q[0][0] < cutoff:
                q.popleft()

            unique_subs = {sub for _, sub in q if sub}
            if len(unique_subs) >= self.subdomain_burst_threshold:
                score += 2
                reasons.append(f"High unique subdomain rate ({len(unique_subs)} distinct subdomains in {self.window_seconds}s)")

        if score >= self.score_threshold:
            return [
                Alert(
                    alert_type="dns_tunnel",
                    severity="high" if score >= self.score_threshold + 2 else "medium",
                    src=src,
                    dst=event.dst,
                    description=f"Suspected DNS tunneling/exfiltration from {src} querying {qname}: {', '.join(reasons)}",
                    evidence={
                        "qname": qname,
                        "subdomain": subdomain,
                        "parent_domain": parent,
                        "entropy": round(entropy, 2),
                        "query_length": len(qname),
                        "dns_qtype": event.dns_qtype,
                        "score": score,
                        "reasons": reasons,
                    },
                    ts=event.ts
                )
            ]

        return []

    def reset(self) -> None:
        self.query_history.clear()
