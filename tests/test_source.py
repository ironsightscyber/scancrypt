import os
import random

import pytest

from rprt import source


@pytest.fixture
def data_file(tmp_path):
    """Unaligned total size -- exercises the end-of-device clamping edge case."""
    rng = random.Random(3)
    data = bytes(rng.getrandbits(8) for _ in range(3 * 4096 + 1234))
    path = tmp_path / "data.bin"
    path.write_bytes(data)
    return str(path), data


@pytest.fixture
def aligned_data_file(tmp_path):
    """Size is a multiple of the 4096 alignment, like a real block device."""
    rng = random.Random(4)
    data = bytes(rng.getrandbits(8) for _ in range(8 * 4096))
    path = tmp_path / "aligned.bin"
    path.write_bytes(data)
    return str(path), data


def _aligned_read(path, data, offset, length, align=4096):
    with open(path, "rb") as f:
        return source.aligned_read(f, len(data), offset, length, align)


def test_aligned_read_matches_slice_at_unaligned_offsets(aligned_data_file):
    path, data = aligned_data_file
    cases = [
        (0, 100),            # aligned start
        (1, 100),            # off-by-one start
        (4095, 2),           # straddles an alignment boundary
        (5000, 4096),        # unaligned start, aligned length
        (8191, 8193),        # spans multiple aligned chunks
    ]
    for offset, length in cases:
        assert _aligned_read(path, data, offset, length) == data[offset:offset + length]


def test_aligned_read_clamps_at_end(data_file):
    path, data = data_file
    # The last 1234 bytes sit past the final full 4096-sector. A raw device can only
    # serve whole sectors, so aligned_read must clamp to the last full sector rather
    # than ask the kernel for a partial one.
    last_full = (len(data) // 4096) * 4096
    got = _aligned_read(path, data, last_full - 100, 5000)
    assert got == data[last_full - 100:last_full]


def test_aligned_read_past_end_returns_empty(data_file):
    path, data = data_file
    assert _aligned_read(path, data, len(data) + 10, 100) == b""
    assert _aligned_read(path, data, 0, 0) == b""


def test_file_source_read_at(data_file):
    path, data = data_file
    with source.FileSource(path) as src:
        assert src.size == len(data)
        assert src.read_at(10, 50) == data[10:60]
        assert src.read_at(len(data) - 5, 100) == data[-5:]


def test_is_scannable(data_file, tmp_path):
    path, _ = data_file
    assert source.is_scannable(path)
    assert not source.is_scannable(str(tmp_path / "missing.bin"))
    # device-path syntax is only meaningful on Windows
    import sys
    expected = sys.platform == "win32"
    assert source.is_raw_device("\\\\.\\PhysicalDrive1") is expected
