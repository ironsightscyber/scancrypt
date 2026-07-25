import os
import random

import pytest


def _random_bytes(n: int, seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def _plausible_text_bytes(n: int, seed: int) -> bytes:
    """Low-entropy filler that reads as 'intact', unlike pure random bytes."""
    rng = random.Random(seed)
    alphabet = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJ0123456789\n"
    return bytes(alphabet[rng.randrange(len(alphabet))] for _ in range(n))


@pytest.fixture
def front_only_file(tmp_path):
    """Small encrypted header, large intact body -- the Makop/Phobos pattern.

    Encrypted region is kept well above the default sample size (64 KB) so the
    binary-search refine doesn't read samples that straddle the boundary and
    mix encrypted+intact bytes into one ambiguous entropy reading -- the same
    proportions (encrypted region orders of magnitude bigger than the sample
    window) held in the real sample this was validated against.
    """
    encrypted_len = 2 * 1024 * 1024
    intact_len = 6 * 1024 * 1024
    data = _random_bytes(encrypted_len, seed=1) + _plausible_text_bytes(intact_len, seed=2)
    path = tmp_path / "front_only.bin"
    path.write_bytes(data)
    return str(path), encrypted_len, encrypted_len + intact_len


@pytest.fixture
def periodic_file(tmp_path):
    """Regular-size, regular-spacing high-entropy runs throughout the file."""
    block_size = 8192
    total_blocks = 200
    run_len_blocks = 2
    gap_blocks = 8

    chunks = []
    i = 0
    while i < total_blocks:
        if i % gap_blocks == 0:
            for _ in range(run_len_blocks):
                chunks.append(_random_bytes(block_size, seed=i))
                i += 1
        else:
            chunks.append(_plausible_text_bytes(block_size, seed=i))
            i += 1
    data = b"".join(chunks)
    path = tmp_path / "periodic.bin"
    path.write_bytes(data)
    return str(path), block_size


@pytest.fixture
def scattered_benign_file(tmp_path):
    """Irregular-size, irregular-spacing high-entropy blocks -- e.g. compressed LOB
    data mixed into an otherwise intact file. Should NOT be classified as encrypted."""
    block_size = 8192
    rng = random.Random(42)
    chunks = []
    for i in range(300):
        if rng.random() < 0.05:
            run_len = rng.randint(1, 4)
            for _ in range(run_len):
                chunks.append(_random_bytes(block_size, seed=1000 + i))
        else:
            chunks.append(_plausible_text_bytes(block_size, seed=i))
    data = b"".join(chunks)
    path = tmp_path / "scattered.bin"
    path.write_bytes(data)
    return str(path), block_size


@pytest.fixture
def front_only_with_isolated_noise_file(tmp_path):
    """Front-only encrypted region PLUS two isolated, unrelated high-entropy patches
    far away in the file (e.g. dense filesystem content) -- the exact shape of data
    that caused a real false-positive boundary (~312 MB reported instead of true
    ~1 MB) when the boundary search anchored on 'the last encrypted sample found
    anywhere' instead of the contiguous run from offset 0. This fixture guards
    against regressing to that behaviour.
    """
    encrypted_len = 2 * 1024 * 1024
    total_len = 16 * 1024 * 1024
    noise_len = 128 * 1024

    buf = bytearray(_plausible_text_bytes(total_len, seed=5))
    buf[0:encrypted_len] = _random_bytes(encrypted_len, seed=1)

    noise_offset_1 = 6 * 1024 * 1024
    noise_offset_2 = 12 * 1024 * 1024
    buf[noise_offset_1:noise_offset_1 + noise_len] = _random_bytes(noise_len, seed=11)
    buf[noise_offset_2:noise_offset_2 + noise_len] = _random_bytes(noise_len, seed=12)

    path = tmp_path / "front_only_with_noise.bin"
    path.write_bytes(bytes(buf))
    return str(path), encrypted_len, [noise_offset_1, noise_offset_2]


@pytest.fixture
def front_plus_large_second_region_file(tmp_path):
    """A front-encrypted region PLUS a large *contiguous* second encrypted region far past
    the boundary -- a genuinely non-contiguous encryption pattern (not scattered noise).
    This must still escalate to a full scan, where the front-only-vs-noise heuristic must
    NOT dismiss it. Contrast with front_only_with_isolated_noise_file (tiny scattered
    patches that must NOT escalate)."""
    front_len = 2 * 1024 * 1024
    total_len = 64 * 1024 * 1024
    region_off = 24 * 1024 * 1024
    region_len = 8 * 1024 * 1024                     # 12.5% of the file, one contiguous run

    buf = bytearray(_plausible_text_bytes(total_len, seed=5))
    buf[0:front_len] = _random_bytes(front_len, seed=1)
    buf[region_off:region_off + region_len] = _random_bytes(region_len, seed=21)

    path = tmp_path / "front_plus_second_region.bin"
    path.write_bytes(bytes(buf))
    return str(path), front_len, region_off, region_len


@pytest.fixture
def fully_encrypted_file(tmp_path):
    data = _random_bytes(2 * 1024 * 1024, seed=99)
    path = tmp_path / "fully_encrypted.bin"
    path.write_bytes(data)
    return str(path)


@pytest.fixture
def fully_intact_file(tmp_path):
    data = _plausible_text_bytes(2 * 1024 * 1024, seed=7)
    path = tmp_path / "fully_intact.bin"
    path.write_bytes(data)
    return str(path)
