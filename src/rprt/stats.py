"""rprt.stats — statistical randomness tests to tell *encrypted* from *compressed*.

Shannon entropy cannot separate the two: AES output and a DEFLATE/JPEG/LOB blob both
read ~8.0 bits/byte. But encrypted data is statistically *uniform random*, while most
compressed data is not -- it carries residual structure that shows up as a byte-value
distribution measurably further from uniform.

The discriminator here is the chi-square goodness-of-fit statistic against a uniform
byte distribution. Its key property: under true uniformity the statistic has expected
value (bins-1)=255 and variance 2*255, **independent of block size** (given enough bytes
per bin). So a fixed ceiling a few sigma above 255 almost never mislabels encrypted data
(high precision), while compressed content -- whose distribution deviates -- exceeds it.

Measured against real data (this repo's calibration run):
  - encrypted / cryptographic-random: chi-square clusters at ~255 at every block size.
  - zlib/DEFLATE (ZIP, OOXML, PNG, gzip -- the common cases): clearly elevated; cleanly
    separable at >= 16 KiB, and separable as a run-mean at 8 KiB.
  - bzip2: elevated (mostly separable).
  - LZMA/xz (7z): statistically uniform -- NOT separable from encryption by this test.

So this REFINES classification (mainly: stop flagging compressed content as encrypted)
without ever reclassifying genuinely random/encrypted data. It is not a silver bullet:
LZMA-class compression is indistinguishable from encryption on distribution alone, and
that limit is surfaced rather than hidden.
"""
from __future__ import annotations

import math

try:
    import numpy as _np
except ImportError:
    _np = None

CHI2_DOF = 255                       # 256 byte-value bins - 1
_CHI2_STD = math.sqrt(2 * CHI2_DOF)  # ~22.58

# Ceiling above which a block's byte distribution is "too structured to be encryption".
# 4 sigma above the uniform mean -> ~3e-5 chance of a truly-random block exceeding it, so
# encrypted data is essentially never mislabelled. Recall (catching compression) depends
# on block size and compressor, by design -- precision is the invariant we protect.
CHI2_CEILING = CHI2_DOF + 4.0 * _CHI2_STD           # ~345.3

# For a *run* of blocks the mean chi-square has much lower variance, so a tighter cut
# cleanly separates a run of compressed blocks (mean well above 300) from a run of random
# ones (mean ~255).
CHI2_RUN_CEILING = 300.0

# Below this block size the test is unreliable (too few expected counts per bin).
MIN_CHI2_BLOCK = 2048


def chi_square_uniform(data: bytes) -> float:
    """Chi-square goodness-of-fit of the byte-value histogram to a uniform distribution.
    ~255 for uniform-random (encrypted) data; higher the more structured the bytes are."""
    n = len(data)
    if n == 0:
        return 0.0
    if _np is not None:
        counts = _np.bincount(_np.frombuffer(data, dtype=_np.uint8), minlength=256)
    else:
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        counts = counts  # list works below
    expected = n / 256.0
    if _np is not None:
        return float(((counts - expected) ** 2 / expected).sum())
    return sum((c - expected) ** 2 / expected for c in counts)


def looks_compressed(chi2: float, block_size: int) -> bool:
    """True if a single block's chi-square is high enough to indicate structured
    (compressed) content rather than encryption. Requires an adequate block size; on too
    small a block the test can't be trusted, so it returns False (defer to other signals)."""
    return block_size >= MIN_CHI2_BLOCK and chi2 > CHI2_CEILING


def run_looks_compressed(mean_chi2: float) -> bool:
    """True if the mean chi-square across a run of high-entropy blocks indicates the run is
    compressed content rather than encryption."""
    return mean_chi2 > CHI2_RUN_CEILING


# Compression/archive stream headers long or constrained enough that they essentially never
# occur by chance (the shortest here is 4 bytes -> ~1 in 4 GB; xz/7z are 6 bytes -> never).
# Encryption produces NONE of these; strongly-compressed content (Docker image layers, archives)
# is full of them at stream boundaries. This is the structural signal that catches compressed
# data so tightly packed it is statistically uniform -- where entropy AND chi-square both read
# it as random and would otherwise call it ciphertext. Deliberately excludes the bare 2-byte
# gzip magic (chance ~1 per 64 KB) so it can never mislabel a large encrypted run as compressed.
_COMPRESSION_MAGICS = (
    b"\x1f\x8b\x08\x00", b"\x1f\x8b\x08\x08",           # gzip (deflate; common flag bytes)
    b"\xfd7zXZ\x00",                                     # xz
    b"\x28\xb5\x2f\xfd",                                 # zstd
    b"PK\x03\x04",                                       # zip / jar / OOXML
    b"\x04\x22\x4d\x18",                                 # lz4 frame
    b"7z\xbc\xaf\x27\x1c",                               # 7z
) + tuple(b"BZh" + bytes([d]) for d in range(0x31, 0x3a))   # bzip2, BZh1..BZh9


def reliable_compression_magic_count(data: bytes) -> int:
    """How many high-reliability compression/archive stream headers appear in `data`. See
    _COMPRESSION_MAGICS: used as a structural companion to the chi-square test so that strongly
    compressed (statistically uniform) content is not mistaken for encryption."""
    return sum(data.count(m) for m in _COMPRESSION_MAGICS)
