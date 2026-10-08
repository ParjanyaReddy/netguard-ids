import hashlib
from typing import List, Tuple, Optional


class CountMinSketch:
    """
    Count-Min Sketch (CMS) probabilistic data structure with Conservative Update (CMS-CU).
    
    Provides bounded-memory frequency estimation for high-cardinality streams
    (e.g., tracking millions of (src_ip, dst_port) pairs without OOM crashes).
    Memory footprint is strictly fixed to width * depth * 4 bytes.
    """
    def __init__(self, width: int = 2048, depth: int = 4, conservative_update: bool = True):
        self.width = width
        self.depth = depth
        self.conservative_update = conservative_update
        # 2D table of integer counters: depth rows x width columns
        self.table: List[List[int]] = [[0] * self.width for _ in range(self.depth)]
        # Precomputed salt strings for independent hashing across rows
        self._salts = [f"seed_{i}".encode("utf-8") for i in range(self.depth)]

    def _hash(self, key_bytes: bytes, row: int) -> int:
        """
        Computes row-specific hash using blake2b with precomputed salt.
        Returns a column index in [0, self.width - 1].
        """
        digest = hashlib.blake2b(key_bytes, digest_size=8, salt=self._salts[row]).digest()
        # Fast 64-bit unsigned int conversion
        val = int.from_bytes(digest, byteorder="big", signed=False)
        return val % self.width

    def add(self, key: str, count: int = 1) -> None:
        """
        Increments frequency for a key. If conservative_update is True,
        only the counters holding the minimum candidate value are incremented,
        significantly reducing overestimation due to collisions.
        """
        key_bytes = key.encode("utf-8")
        indices = [self._hash(key_bytes, r) for r in range(self.depth)]

        if not self.conservative_update:
            for r, c in enumerate(indices):
                self.table[r][c] += count
            return

        # Conservative Update (CMS-CU) heuristic
        current_vals = [self.table[r][c] for r, c in enumerate(indices)]
        min_val = min(current_vals)
        for r, c in enumerate(indices):
            if self.table[r][c] == min_val:
                self.table[r][c] += count

    def estimate(self, key: str) -> int:
        """
        Returns the frequency estimate for key (minimum across all rows).
        """
        key_bytes = key.encode("utf-8")
        min_val = float("inf")
        for r in range(self.depth):
            c = self._hash(key_bytes, r)
            val = self.table[r][c]
            if val < min_val:
                min_val = val
        return int(min_val)

    def decay(self, factor: float = 0.5) -> None:
        """
        Multiplies all counters by decay factor to age out historical counts
        over sliding time epochs.
        """
        for r in range(self.depth):
            for c in range(self.width):
                self.table[r][c] = int(self.table[r][c] * factor)

    def clear(self) -> None:
        """Resets all counters in the sketch to zero."""
        for r in range(self.depth):
            self.table[r] = [0] * self.width

    @property
    def memory_bytes(self) -> int:
        """Returns approximate fixed memory footprint of the counter matrix in bytes."""
        # 4 bytes per 32-bit counter
        return self.width * self.depth * 4
