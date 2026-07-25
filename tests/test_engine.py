import os

from rprt import engine


def test_front_only_boundary_detected(front_only_file):
    path, encrypted_len, total_len = front_only_file
    report = engine.scan(path)
    assert report.pattern == "front-only"
    # binary search refines to within REFINE_PRECISION bytes of the true boundary
    assert abs(report.boundary_offset - encrypted_len) <= engine.REFINE_PRECISION
    assert report.size == total_len


def test_boundary_ignores_isolated_noise_elsewhere_in_file(front_only_with_isolated_noise_file):
    """Regression test for the real false-positive found during prototype testing:
    isolated high-entropy content far from the front must not inflate the reported
    boundary. See conftest.front_only_with_isolated_noise_file for the incident this
    mirrors (~312 MB false boundary instead of true ~1 MB).

    Calls boundary_scan() directly (not the adaptive scan() entry point) so this
    isolates the anchor-point fix from full_scan()'s separate run-regularity
    classifier (see test_full_scan_separates_dominant_run_from_isolated_noise and
    test_scan_adaptive_entry_point_recognizes_mixed_front_and_noise for that case).
    """
    path, encrypted_len, noise_offsets = front_only_with_isolated_noise_file
    report = engine.boundary_scan(path)

    assert abs(report.boundary_offset - encrypted_len) <= engine.REFINE_PRECISION
    for noise_off in noise_offsets:
        assert not (noise_off - 200_000 <= report.boundary_offset <= noise_off + 200_000)

    assert report.isolated_high_entropy_offsets
    for noise_off in noise_offsets:
        assert any(abs(o - noise_off) < 200_000 for o in report.isolated_high_entropy_offsets)


def test_fully_encrypted_detected(fully_encrypted_file):
    report = engine.scan(fully_encrypted_file)
    assert report.pattern == "fully-encrypted"
    assert report.encrypted_bytes == report.size


def test_fully_intact_detected(fully_intact_file):
    report = engine.scan(fully_intact_file)
    assert report.pattern == "fully-intact"
    assert report.encrypted_bytes == 0
    assert report.recoverable_pct == 100.0


def test_tightly_compressed_blob_not_flagged_as_encryption(tmp_path):
    """Regression: data compressed so tightly it is statistically uniform (chi-square ~255,
    identical to AES ciphertext) must not read as encrypted. The structural signal -- reliable
    compression-stream headers, which ciphertext never contains -- catches it. Modelled on a
    real Docker-image xz layer that made a naive scan report a header-encrypted disk as
    partly encrypted."""
    import random
    buf = bytearray(random.Random(7).randbytes(8 * 1024 * 1024))   # uniform-random
    for off in range(0, len(buf), 16384):
        buf[off:off + 6] = b"\xfd7zXZ\x00"                          # xz stream header
    p = tmp_path / "compressed.bin"
    p.write_bytes(buf)
    report = engine.full_scan(str(p), block_size=8192)
    assert report.pattern == "compressed-benign"
    assert report.encrypted_bytes == 0

    # control: the same bytes WITHOUT the stream headers are indistinguishable from ciphertext
    plain = tmp_path / "random.bin"
    plain.write_bytes(random.Random(7).randbytes(8 * 1024 * 1024))
    assert engine.full_scan(str(plain), block_size=8192).pattern == "fully-encrypted"


def test_periodic_pattern_classified_via_full_scan(periodic_file):
    path, block_size = periodic_file
    report = engine.full_scan(path, block_size=block_size)
    assert report.pattern == "periodic-intermittent"


def test_scattered_benign_not_flagged_as_encryption(scattered_benign_file):
    path, block_size = scattered_benign_file
    report = engine.full_scan(path, block_size=block_size)
    assert report.pattern == "scattered-benign"


def test_full_scan_separates_dominant_run_from_isolated_noise(front_only_with_isolated_noise_file):
    """A genuine large front-encrypted run plus small, irregular high-entropy noise
    elsewhere must not be washed out into 'scattered-benign' -- the dominant run should
    still be recognized as a real contiguous encrypted region."""
    path, encrypted_len, noise_offsets = front_only_with_isolated_noise_file
    report = engine.full_scan(path, block_size=8192)

    assert report.pattern in ("front-only", "mixed")
    assert report.pattern != "scattered-benign"

    runs = report.run_length_sample
    assert runs, "expected at least one run in the sample"
    dominant_run = max(runs, key=lambda r: r[1])
    dominant_bytes = dominant_run[1] * report.block_size
    assert abs(dominant_bytes - encrypted_len) <= report.block_size * 4


def test_scan_does_not_escalate_on_isolated_noise(front_only_with_isolated_noise_file):
    """scan() must NOT burn a full O(size) block scan just because a couple of isolated
    high-entropy patches sit past the front boundary -- that is benign dense content on
    every real disk image. It stays a fast boundary result (front-only), reports the
    patches as isolated points, and keeps the true boundary (not inflated by the noise)."""
    path, encrypted_len, noise_offsets = front_only_with_isolated_noise_file
    report = engine.scan(path)

    assert report.mode == "boundary"          # fast path retained, no full scan
    assert report.pattern == "front-only"
    assert abs(report.boundary_offset - encrypted_len) <= engine.REFINE_PRECISION
    assert report.isolated_high_entropy_offsets
    for noise_off in noise_offsets:
        assert any(abs(o - noise_off) < 200_000 for o in report.isolated_high_entropy_offsets)


def test_scan_escalates_on_large_second_region(front_plus_large_second_region_file):
    """A genuine second encrypted region -- a large contiguous high-entropy run past the
    front boundary, not scattered noise -- must still escalate to a full block scan so it
    gets mapped, and must not be dismissed as front-only."""
    path, front_len, region_off, region_len = front_plus_large_second_region_file
    report = engine.scan(path)
    assert report.mode == "full"
    assert report.pattern != "front-only"


def test_boundary_only_skips_escalation(front_plus_large_second_region_file):
    """--boundary-only (boundary_only=True) accepts the fast boundary even when a full scan
    would otherwise be triggered -- for a huge slow disk where the boundary is enough."""
    path, front_len, region_off, region_len = front_plus_large_second_region_file
    report = engine.scan(path, boundary_only=True)
    assert report.mode == "boundary"


def test_boundary_extraction_recovers_intact_bytes(tmp_path, front_only_file):
    path, encrypted_len, total_len = front_only_file
    report = engine.scan(path)
    out_path = str(tmp_path / "recovered.bin")
    written = engine.extract_intact_ranges(path, report, out_path)

    assert written == os.path.getsize(out_path)
    assert written == total_len - report.boundary_offset

    with open(path, "rb") as f:
        f.seek(report.boundary_offset)
        expected_tail = f.read()
    with open(out_path, "rb") as f:
        actual = f.read()
    assert actual == expected_tail


def test_full_scan_extraction_drops_only_encrypted_blocks(tmp_path, periodic_file):
    path, block_size = periodic_file
    report = engine.full_scan(path, block_size=block_size)
    out_path = str(tmp_path / "recovered.bin")
    written = engine.extract_intact_ranges(path, report, out_path)

    # every retained block must itself be non-high-entropy
    with open(out_path, "rb") as f:
        data = f.read()
    assert written == len(data)
    for i in range(0, len(data) - block_size + 1, block_size):
        block = data[i:i + block_size]
        assert engine.shannon_entropy(block) <= engine.ENCRYPTED_THRESHOLD

    # extraction must shrink the file relative to the original (some bytes dropped)
    assert written < os.path.getsize(path)


def test_chunk_entropies_matches_scalar_reference():
    """The numpy-vectorised per-block stats must agree with the scalar reference for
    entropy, all-zero detection, and the chi-square statistic."""
    import random
    from rprt import stats as stats_mod
    rng = random.Random(8)
    block_size = 1024
    blocks = [
        bytes(rng.getrandbits(8) for _ in range(block_size)),      # random
        (b"abc " * 300)[:block_size],                              # low entropy
        b"\x00" * block_size,                                      # all zero
        bytes([7]) * block_size,                                   # single symbol, nonzero
    ]
    data = b"".join(blocks)
    stats = engine._chunk_stats(data, block_size)
    assert len(stats) == len(blocks)
    for b, (ent, zero, chi2) in zip(blocks, stats):
        assert abs(ent - engine.shannon_entropy(b)) < 1e-9
        assert zero == (b.count(0) == len(b))
        assert abs(chi2 - stats_mod.chi_square_uniform(b)) < 1e-6


def test_cancel_stops_scan(front_only_file):
    path, _, _ = front_only_file
    calls = {"n": 0}

    def cancel_after_first_progress():
        calls["n"] += 1
        return calls["n"] > 1

    try:
        engine.boundary_scan(path, cancel_check=cancel_after_first_progress)
        raised = False
    except engine.Cancelled:
        raised = True
    assert raised


# ---------------------------------------------------------------- volume image cutting

def _boot_sector(bps=512, total_sectors=64):
    bs = bytearray(512)
    bs[3:11] = b"NTFS    "
    bs[0x0B:0x0D] = bps.to_bytes(2, "little")
    bs[0x28:0x30] = total_sectors.to_bytes(8, "little")
    return bytes(bs)


def test_ntfs_volume_length_from_boot_sector(tmp_path):
    off = 1024
    p = tmp_path / "img.bin"
    p.write_bytes(b"\xAA" * off + _boot_sector(512, 64) + b"\xBB" * (65 * 512))
    # 64 data sectors + 1 backup boot sector
    assert engine.ntfs_volume_length(str(p), off) == 65 * 512


def test_ntfs_volume_length_rejects_garbage(tmp_path):
    p = tmp_path / "img.bin"
    p.write_bytes(b"\x00" * 4096)
    assert engine.ntfs_volume_length(str(p), 0) is None
    # right magic, absurd sector size
    p.write_bytes(_boot_sector(bps=123, total_sectors=64) + b"\x00" * 4096)
    assert engine.ntfs_volume_length(str(p), 0) is None


def test_extract_range_cuts_exact_window(tmp_path):
    data = bytes(range(256)) * 64            # 16 KB, recognisable
    p = tmp_path / "img.bin"
    p.write_bytes(data)
    out = tmp_path / "cut.img"
    written = engine.extract_range(str(p), 1000, 5000, str(out))
    assert written == 5000
    assert out.read_bytes() == data[1000:6000]


def test_extract_range_none_length_reads_to_end(tmp_path):
    data = b"x" * 3000
    p = tmp_path / "img.bin"
    p.write_bytes(data)
    out = tmp_path / "cut.img"
    assert engine.extract_range(str(p), 1200, None, str(out)) == 1800
    assert out.read_bytes() == data[1200:]


def test_extract_volume_end_to_end_starts_at_boot_sector(tmp_path):
    # An "image": encrypted-looking front, then an intact NTFS volume. The cut volume
    # image must begin with the boot sector so 7-Zip-style tools can open it.
    import random
    rng = random.Random(7)
    vol_off = 512 * 16
    total_sectors = 32
    front = bytes(rng.getrandbits(8) for _ in range(vol_off))
    volume = _boot_sector(512, total_sectors) + b"F" * (total_sectors * 512)
    p = tmp_path / "disk.img"
    p.write_bytes(front + volume + b"\x00" * 2048)

    from rprt import cli
    out = tmp_path / "vol.ntfs.img"
    rc = cli.main([str(p), "--extract-volume", str(out)])
    assert rc == 0
    got = out.read_bytes()
    assert got[3:11] == b"NTFS    "
    assert len(got) == (total_sectors + 1) * 512
