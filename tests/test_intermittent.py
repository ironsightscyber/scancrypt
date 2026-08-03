"""Intermittent (striped) encryption must be measured, not under-reported.

The scanner once reported striped files as front-only -- or, when the stripes were narrower
than the scan block, as fully-intact and 100% recoverable. Every failure ran in the same
direction: claiming more was recoverable than was true. Extracting on that answer returns a
file with ciphertext stitched through it, which is worse than being told it is unrecoverable.

These tests fix the measured behaviour in place. Sizes are kept small (2-4 MiB) so the whole
module runs in a few seconds; the striping ratios, not the absolute sizes, are what the
detection reads.
"""
import random
import zlib

import pytest

from rprt import engine

KIB = 1024
MIB = 1024 * 1024


def _plaintext(rng, n):
    """Low-entropy record-structured filler, standing in for the recoverable content."""
    out = bytearray()
    i = 0
    while len(out) < n:
        i += 1
        out += (f"REC{i:09d}|Sandra Whitfield|Townsville|"
                f"{rng.randrange(1000, 9999)}|ACTIVE|\n").encode("ascii")
    return bytes(out[:n])


def _write_striped(path, total, stride, slice_len, seed):
    """Write `total` bytes where each `stride` begins with `slice_len` cipher-like bytes.

    Returns the true encrypted byte count. Seeded, so a failure is reproducible.
    """
    rng = random.Random(seed)
    written = encrypted = 0
    with open(path, "wb") as fh:
        while written < total:
            block = min(stride, total - written)
            enc = min(slice_len, block)
            fh.write(rng.randbytes(enc))
            encrypted += enc
            if block > enc:
                fh.write(_plaintext(rng, block - enc))
            written += block
    return encrypted


# (label, total, stride, slice_len). The sub-block cases matter most: a stripe narrower than
# the 8192-byte default scan block averages out against the plaintext around it, which is how
# a 6.25%-encrypted file came to be reported as fully intact.
STRIPE_PATTERNS = [
    ("8KiB-every-128KiB", 4 * MIB, 128 * KIB, 8 * KIB),
    ("32KiB-every-256KiB", 4 * MIB, 256 * KIB, 32 * KIB),
    ("8KiB-every-64KiB", 2 * MIB, 64 * KIB, 8 * KIB),
    ("2KiB-every-32KiB-sub-block", 4 * MIB, 32 * KIB, 2 * KIB),
    ("4KiB-every-64KiB-sub-block", 8 * MIB, 64 * KIB, 4 * KIB),
]


@pytest.mark.parametrize("label,total,stride,slice_len", STRIPE_PATTERNS,
                         ids=[p[0] for p in STRIPE_PATTERNS])
@pytest.mark.parametrize("seed", [101, 202])
def test_striped_encryption_is_measured_exactly(tmp_path, label, total, stride,
                                                 slice_len, seed):
    """The default scan -- no --full, no --block-size -- must find every encrypted byte."""
    path = tmp_path / f"{label}_{seed}.img"
    truth = _write_striped(path, total, stride, slice_len, seed)

    report = engine.scan(str(path))

    assert report.encrypted_bytes == truth, (
        f"{label} seed={seed}: reported {report.encrypted_bytes:,} of {truth:,} encrypted "
        f"bytes as '{report.pattern}'. Under-reporting overstates recoverability."
    )
    assert report.pattern == "periodic-intermittent"


def test_sub_block_stripes_are_not_reported_as_intact(tmp_path):
    """The specific regression: 4 KiB stripes inside an 8 KiB block once read as clean.

    Both the default scan and --full reported fully-intact and 100% recoverable on a file
    that was 6.25% ciphertext."""
    path = tmp_path / "sub_block.img"
    truth = _write_striped(path, 8 * MIB, 64 * KIB, 4 * KIB, seed=7)

    report = engine.scan(str(path))

    assert report.pattern != "fully-intact"
    assert report.encrypted_bytes == truth
    assert report.recoverable_pct == pytest.approx(93.75, abs=0.01)


@pytest.mark.parametrize("name", ["data.mdf", "data.mdf.[ID-9F2C].ndm448", "data.mdf.lockbit"])
def test_detection_does_not_depend_on_the_filename(tmp_path, name):
    """Identical content must measure identically however the file is named.

    ScanCrypt used to identify a file as LockBit 2.0, read large_file_pattern:
    periodic-intermittent from its own signature database, and still report it fully intact.
    The fix is evidence-driven, so the unhinted name must work too -- otherwise detection
    silently depends on recognising the family."""
    path = tmp_path / name
    truth = _write_striped(path, 4 * MIB, 64 * KIB, 4 * KIB, seed=11)

    report = engine.scan(str(path))

    assert report.encrypted_bytes == truth
    assert report.pattern == "periodic-intermittent"


def test_plain_content_is_not_flagged_by_the_escalation(tmp_path):
    """The extra scan passes must not invent encryption in an ordinary file."""
    path = tmp_path / "plain.txt"
    path.write_bytes(_plaintext(random.Random(3), 3 * MIB))

    report = engine.scan(str(path))

    assert report.encrypted_bytes == 0
    assert report.recoverable_pct == 100.0


def test_compressed_content_is_not_flagged_by_the_escalation(tmp_path):
    """Real DEFLATE reads ~8 bits/byte like ciphertext. It must still come back recoverable."""
    rng = random.Random(4)
    out = bytearray()
    while len(out) < 3 * MIB:
        out += zlib.compress(_plaintext(rng, 512 * KIB), 9)
    path = tmp_path / "compressed.bin"
    path.write_bytes(bytes(out[:3 * MIB]))

    report = engine.scan(str(path))

    assert report.encrypted_bytes == 0


# ---------------------------------------------------------------- scan-mode agreement
#
# The two scan modes must not contradict each other on the same file. They did: --full, the
# mode the GUI offers as "slower, catches scattered/periodic encryption", could not detect
# front-only encryption at all and reported 100% recoverable on files the boundary scan
# measured exactly. Front-only is the most common ransomware pattern, so the thorough option
# was the one that missed it.

def _write_front_only(path, total, encrypted, seed):
    rng = random.Random(seed)
    with open(path, "wb") as fh:
        fh.write(rng.randbytes(encrypted))
        remaining = total - encrypted
        while remaining > 0:
            chunk = min(4 * MIB, remaining)
            fh.write(_plaintext(rng, chunk))
            remaining -= chunk
    return encrypted


# Encrypted lengths are whole multiples of the 8192-byte scan block so both modes can be
# asserted exactly; full mode counts whole blocks and would otherwise round down.
FRONT_ONLY_CASES = [
    ("1MiB-front-of-16MiB", 16 * MIB, 1 * MIB),
    ("64KiB-front-of-8MiB", 8 * MIB, 64 * KIB),
]


@pytest.mark.parametrize("label,total,encrypted", FRONT_ONLY_CASES,
                         ids=[c[0] for c in FRONT_ONLY_CASES])
@pytest.mark.parametrize("full", [False, True], ids=["boundary", "full"])
def test_front_only_detected_in_both_scan_modes(tmp_path, label, total, encrypted, full):
    path = tmp_path / f"{label}.img"
    truth = _write_front_only(path, total, encrypted, seed=31)

    report = engine.scan(str(path), full=full)

    assert report.pattern == "front-only", (
        f"{label} in {'full' if full else 'boundary'} mode reported '{report.pattern}' "
        f"({report.encrypted_bytes:,} encrypted) for a file with a {truth:,}-byte "
        f"encrypted front."
    )
    assert report.encrypted_bytes == truth


def test_single_run_at_offset_zero_is_front_only_not_scattered():
    """A lone high-entropy run anchored at offset 0 is the front-only signature.

    It cannot reach the dominant-run split -- with one run there is nothing to be an outlier
    against, since its own length is the median -- so before the fix it fell through to the
    regularity check, which cannot judge spacing from a single run and returned
    scattered-benign. Runs are (start_block, length)."""
    pattern, note = engine._classify_runs([(0, 128)], nblocks=12800)
    assert pattern == "front-only", note


def test_single_run_away_from_offset_zero_is_not_front_only():
    """The anchor matters: an isolated dense region in the middle of a file is ordinary
    content (LOB pages, an embedded image), not an encrypted front."""
    pattern, _ = engine._classify_runs([(4000, 128)], nblocks=12800)
    assert pattern != "front-only"


# ---------------------------------------------------------------- stride detection units
#
# The two cases below are the false starts that cost real debugging time. Both looked correct
# on one sample and failed on another, so they are pinned here rather than left to a sweep.

def test_cluster_offsets_merges_a_stripe_spanning_several_samples():
    """A stripe wider than the sampling step lights up consecutive samples.

    Deriving the merge threshold from the *median* gap fails here: the median IS the
    within-stripe spacing, so the threshold lands below every gap and nothing merges."""
    coarse_step = 262144
    offsets = [8388608, 8650752,
               16777216, 17039360,
               25165824, 25427968,
               33554432, 33816576]

    clusters = engine._cluster_offsets(offsets, coarse_step)

    assert clusters == [8388608, 16777216, 25165824, 33554432]
    assert engine._offsets_form_regular_stride(offsets, coarse_step)


def test_cluster_offsets_survives_one_missed_stripe():
    """One stripe the sampler missed leaves a single oversized gap.

    Deriving the threshold from the *maximum* gap fails here: that one gap inflates the
    threshold until every real stripe merges into a single cluster."""
    coarse_step = 131072
    offsets = [1048576, 2097152, 3145728, 4194304, 15728640, 16777216, 17825792]

    clusters = engine._cluster_offsets(offsets, coarse_step)

    assert clusters == offsets, "evenly spaced stripes must not be merged together"
    assert engine._offsets_form_regular_stride(offsets, coarse_step), (
        "a gap that is an exact multiple of the stride is a missed stripe, "
        "not a broken rhythm"
    )


def test_scattered_offsets_are_not_a_stride():
    """Irregularly spaced dense blocks -- LOB pages, media -- must not trigger escalation."""
    coarse_step = 65536
    offsets = [1_000_000, 1_400_000, 3_900_000, 4_050_000, 11_000_000, 30_000_000]

    assert not engine._offsets_form_regular_stride(offsets, coarse_step)


def test_too_few_points_is_not_a_stride():
    """Two points define a gap, not a rhythm."""
    assert not engine._offsets_form_regular_stride([1 * MIB, 2 * MIB], 65536)
