"""Statistical randomness tests distinguishing encrypted from compressed data.

Uses REAL compressed data (zlib/DEFLATE — ZIP/OOXML/PNG/gzip's algorithm) so the tests
exercise the actual discrimination, not a synthetic stand-in. os.urandom models encryption.
"""
import os
import random
import zlib

from rprt import engine, stats


def _text(n, seed):
    rng = random.Random(seed)
    words = [bytes(rng.randrange(97, 123) for _ in range(rng.randint(2, 9))) for _ in range(2000)]
    out = bytearray()
    while len(out) < n:
        out += rng.choice(words) + b" "
    return bytes(out[:n])


def _compressed(n, seed):
    """A block of DEFLATE output at least n bytes long."""
    raw = _text(n * 4, seed)
    return zlib.compress(raw, 9)[:n]


def test_random_chi_square_near_255():
    for bs in (4096, 8192, 65536):
        vals = [stats.chi_square_uniform(os.urandom(bs)) for _ in range(20)]
        mean = sum(vals) / len(vals)
        assert abs(mean - 255) < 40, f"block {bs}: mean chi2 {mean}"


def test_random_not_flagged_compressed():
    # encryption must (essentially) never be called compressed -- precision invariant
    flagged = sum(stats.looks_compressed(stats.chi_square_uniform(os.urandom(65536)), 65536)
                  for _ in range(50))
    assert flagged == 0


def test_deflate_flagged_compressed_at_large_block():
    # at 64 KiB, DEFLATE separates cleanly from random
    hits = 0
    for i in range(30):
        b = _compressed(65536, seed=i)
        if len(b) >= 65536 and stats.looks_compressed(stats.chi_square_uniform(b), 65536):
            hits += 1
    assert hits >= 25, f"expected most DEFLATE blocks flagged, got {hits}/30"


def test_small_blocks_not_trusted():
    # below MIN_CHI2_BLOCK the test defers (returns False) regardless of chi-square
    assert not stats.looks_compressed(9999.0, 512)


def test_entropy_alone_cannot_separate():
    # the premise: entropy of encrypted and compressed are both ~8.0
    enc = engine.shannon_entropy(os.urandom(65536))
    comp = engine.shannon_entropy(_compressed(65536, seed=1))
    assert enc > 7.99 and comp > 7.95
    # yet chi-square does separate them
    assert stats.chi_square_uniform(os.urandom(65536)) < 340
    assert stats.chi_square_uniform(_compressed(65536, seed=1)) > 340
