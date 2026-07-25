"""Block-size-aware entropy threshold.

Grounded in measurements from a real sample: truly-random (encrypted) data reads
BELOW the fixed 7.85 cut-off at small block sizes purely from finite-sample bias
(256-byte ciphertext window ~7.18; 1 KiB ~7.81). The threshold must drop with block
size so encrypted data is not silently classified as intact.
"""
import math
import random

from rprt import engine


def _random_bytes(n, seed):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def test_threshold_never_exceeds_base_and_drops_for_small_blocks():
    assert engine.encrypted_threshold(8192) == engine.ENCRYPTED_THRESHOLD
    assert engine.encrypted_threshold(65536) <= engine.ENCRYPTED_THRESHOLD
    # smaller blocks -> strictly lower threshold
    assert engine.encrypted_threshold(1024) < engine.encrypted_threshold(4096)
    assert engine.encrypted_threshold(256) < engine.encrypted_threshold(1024)


def test_deficit_matches_measured_random_entropy():
    # 8.0 - deficit should predict the entropy of real random data within a few thousandths
    for bs in (4096, 8192, 16384):
        predicted = 8.0 - engine._entropy_deficit(bs)
        measured = engine.shannon_entropy(_random_bytes(bs, seed=bs))
        assert abs(predicted - measured) < 0.01


def test_random_small_blocks_classified_encrypted_with_scaled_threshold():
    # The core regression: at 1 KiB and 512 B, random data reads below 7.85 but must
    # still be classified "encrypted" thanks to the scaled threshold.
    for bs in (512, 1024, 2048, 4096):
        b = _random_bytes(bs, seed=bs + 1)
        e = engine.shannon_entropy(b)
        assert engine._classify_sample(b) == "encrypted", (
            f"block={bs} entropy={e:.4f} threshold={engine.encrypted_threshold(bs):.4f}"
        )


def test_low_entropy_small_blocks_still_intact():
    # Structured/text data at small block sizes must NOT trip the scaled threshold.
    text = (b"the quick brown fox " * 200)
    for bs in (512, 1024, 4096):
        assert engine._classify_sample(text[:bs]) == "intact"


def test_full_scan_with_small_block_size_detects_encryption(tmp_path):
    # A file that is half random, half text, scanned at a 1 KiB block size: the random
    # half must be flagged despite each block reading below the old fixed 7.85.
    half = 256 * 1024
    data = _random_bytes(half, seed=7) + (b"abcd efgh " * (half // 10))[:half]
    path = tmp_path / "mixed.bin"
    path.write_bytes(data)
    report = engine.full_scan(str(path), block_size=1024)
    # roughly half the blocks should be high-entropy; the old code would have found ~none
    assert report.high_entropy_blocks > report.total_blocks * 0.3
