"""Statistical randomness tests distinguishing encrypted from compressed data.

Uses REAL compressed data (zlib/DEFLATE — ZIP/OOXML/PNG/gzip's algorithm) so the tests
exercise the actual discrimination, not a synthetic stand-in. os.urandom models encryption.
"""
import os
import random
import zlib

import numpy as np

from rprt import engine, stats


def _uniform_blocks(count, size, seed):
    """Deterministic uniform-random bytes, standing in for ciphertext.

    Seeded rather than os.urandom because the precision invariant is statistical: at the
    measured ~1.4e-4 false-positive rate, a 50-block assert-exactly-zero test using real
    entropy fails about one run in 130. That is a flaky test, not a regression, and a flaky
    test in this file is worse than useless -- this is the file that backs the tool's central
    accuracy claim, so it has to give the same answer to everyone who runs it."""
    rng = np.random.default_rng(seed)
    for _ in range(count):
        yield rng.integers(0, 256, size, dtype=np.uint8).tobytes()


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
    flagged = sum(stats.looks_compressed(stats.chi_square_uniform(b), 65536)
                  for b in _uniform_blocks(200, 65536, seed=20260803))
    assert flagged == 0


def test_deflate_flagged_compressed_at_8k_block():
    # At 8 KiB a single DEFLATE block separates cleanly from random (mean chi2 ~460 vs a
    # ~345 ceiling). Larger blocks are NOT dependable: zlib-ng (CPython 3.14+) emits output
    # closer to uniform than classic zlib, dropping the 16-64 KiB mean to ~320-350. See the
    # module docstring -- the run-mean, not the single block, is the dependable signal there.
    hits = 0
    for i in range(30):
        b = _compressed(8192, seed=i)
        if len(b) >= 8192 and stats.looks_compressed(stats.chi_square_uniform(b), 8192):
            hits += 1
    assert hits >= 25, f"expected most DEFLATE blocks flagged, got {hits}/30"


def test_deflate_run_flagged_but_random_run_is_not():
    # The signal the engine actually relies on, and the one that holds across deflate
    # implementations: the mean chi-square over a run of blocks.
    for trial in range(5):
        run = [stats.chi_square_uniform(_compressed(8192, seed=trial * 100 + i))
               for i in range(12)]
        mean = sum(run) / len(run)
        assert stats.run_looks_compressed(mean), f"deflate run mean {mean} not flagged"

    for _ in range(5):
        run = [stats.chi_square_uniform(os.urandom(8192)) for _ in range(12)]
        mean = sum(run) / len(run)
        assert not stats.run_looks_compressed(mean), f"random run mean {mean} misflagged"


def test_encrypted_never_misflagged_across_block_sizes():
    # The precision invariant, stated as a test: encryption must never be called compressed,
    # at any block size. Recall varies; this must not.
    for bs in (2048, 8192, 16384, 65536):
        for b in _uniform_blocks(25, bs, seed=bs):
            assert not stats.looks_compressed(stats.chi_square_uniform(b), bs)


def test_small_blocks_not_trusted():
    # below MIN_CHI2_BLOCK the test defers (returns False) regardless of chi-square
    assert not stats.looks_compressed(9999.0, 512)


def test_entropy_alone_cannot_separate():
    # the premise: entropy of encrypted and compressed are both ~8.0
    enc = engine.shannon_entropy(os.urandom(65536))
    comp = engine.shannon_entropy(_compressed(65536, seed=1))
    assert enc > 7.99 and comp > 7.95
    # yet chi-square does separate them. Measured at 8 KiB, where single-block separation
    # holds regardless of deflate implementation -- at 64 KiB under zlib-ng a single block
    # can land below the ceiling, so asserting on one 64 KiB sample would be seed-luck.
    assert stats.chi_square_uniform(os.urandom(8192)) < stats.CHI2_CEILING
    assert stats.chi_square_uniform(_compressed(8192, seed=1)) > stats.CHI2_CEILING
