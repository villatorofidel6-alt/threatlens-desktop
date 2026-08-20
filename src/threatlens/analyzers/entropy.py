"""Small pure helpers for byte-level measurements."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy without modifying or executing the input."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
