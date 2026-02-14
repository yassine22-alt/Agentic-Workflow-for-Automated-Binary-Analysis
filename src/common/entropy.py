"""
Entropy calculation utilities for binary analysis.

Why entropy matters:
- Packed/encrypted sections have high entropy (~7.5-8.0 bits/byte)
- Normal code/data sections have lower entropy (~5.0-6.5 bits/byte)
- Zeros or repeated patterns have very low entropy (~0-2.0 bits/byte)

Shannon entropy formula: H = -Σ p(x) * log₂(p(x))
where p(x) is the probability (frequency) of byte value x
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Counter as CounterType


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy for a byte sequence.
    
    Returns value in bits/byte (0.0 to 8.0).
    - 8.0 = maximum entropy (random/encrypted)
    - 0.0 = minimum entropy (all same byte)
    
    Why this matters for malware analysis:
    - Packers compress code → high entropy
    - Encrypted payloads → high entropy  
    - Normal .text sections → medium entropy (~5.5-6.5)
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    from collections import Counter
    byte_counts: CounterType[int] = Counter(data)
    data_len = len(data)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in byte_counts.values():
        # p(x) = frequency of this byte value
        probability = count / data_len
        # Shannon formula: -p * log₂(p)
        entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_section_entropy(sample_path: Path, offset: int, size: int) -> float:
    """
    Calculate entropy for a specific section/region of a file.
    
    Why per-section instead of whole-file:
    - A 10MB binary with 9.9MB nulls + 100KB shellcode has LOW overall entropy
    - But that 100KB section has HIGH entropy → red flag for analysis
    """
    if size <= 0:
        return 0.0
    
    with sample_path.open("rb") as f:
        f.seek(offset)
        data = f.read(size)
    
    return calculate_entropy(data)
