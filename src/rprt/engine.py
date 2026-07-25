"""
rprt.engine — ransomware partial-encryption entropy mapper.

Core scan/classify/extract logic, adapted from the validated prototype
(prototypes/entropy_map.py) into an importable library the GUI can drive with
progress callbacks and cancellation, instead of a print-and-exit CLI.

Two detection modes:
  - "boundary": assumes a single contiguous encrypted region (the common
    front-only "fast mode" pattern). Coarse scan to bracket the transition,
    then binary-search refine down to a precise byte offset.
  - "full": scans every block. Needed when encryption may be scattered
    throughout the file. Classifies whether high-entropy blocks form a real
    periodic encryption pattern (regular size/spacing) or are just scattered
    high-entropy *content* (compressed/binary data — normal, not encryption).

Inputs go through rprt.source, so a scan target can be a regular file, a disk
image, or (on Windows, running as Administrator) a raw block device like
``\\\\.\\PhysicalDrive1`` — no need to image a disk before triaging it.

Read-only: nothing in this module ever writes to the scanned input.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional

from .source import is_scannable, open_source  # noqa: F401  (is_scannable re-exported for CLI/GUI)
from . import stats as _stats_mod

try:
    import numpy as _np
except ImportError:  # numpy is in our dependencies, but degrade gracefully without it
    _np = None

ENCRYPTED_THRESHOLD = 7.85   # Shannon entropy (bits/byte) above which data reads as random
THRESHOLD_REF_BLOCK = 8192   # block size the 7.85 threshold is calibrated for (one SQL page)
COARSE_STEP_DIVISOR = 256    # first pass: ~256 sample points across the file
REFINE_PRECISION = 4096      # binary-search refine down to this many bytes
FULL_SCAN_CHUNK = 4 * 1024 * 1024  # bytes per sequential read in full-scan mode

# After a clean front boundary is found, high-entropy samples still turn up past it on
# almost every real disk image -- DB index/leaf pages, already-compressed files, thumbnail
# caches. Escalating to a full O(size) block scan for a *single* such sample wastes a whole
# linear read (tens of minutes on a slow disk) and changes the front-only verdict not at
# all: those points are reported separately in `isolated_high_entropy_offsets` regardless.
# Only escalate when the evidence points to a genuine second encrypted region, not scattered
# benign content -- either a large contiguous high-entropy run, or a pervasive fraction of
# the post-boundary spot-checks reading encrypted (the shape of periodic/intermittent
# encryption). Everything below these thresholds stays "front-only" with the points noted.
ESCALATE_SUSPECT_FRACTION = 0.35   # >= this share of post-boundary spot-checks encrypted
ESCALATE_RUN_FRACTION = 0.05       # ...or one contiguous coarse run >= this share of the file

ProgressFn = Optional[Callable[[float, str], None]]


def _entropy_deficit(n: int) -> float:
    """Expected shortfall of the plug-in Shannon estimator below the true 8.0 bits/byte
    for uniformly-random data in a block of `n` bytes: (K-1)/(2 N ln2) with K=256 symbols.
    Measured against real random data this predicts 7.955 at 4 KiB and 7.977 at 8 KiB,
    both matching to three decimals."""
    if n <= 0:
        return 0.0
    return 255.0 / (2.0 * n * math.log(2))


MIN_CLASSIFY_BLOCK = 256   # below this, byte entropy can't fill the symbol space -> unreliable


def encrypted_threshold(block_size: int) -> float:
    """Block-size-aware entropy cut-off. The fixed 7.85 works only for blocks >= ~2 KiB;
    at 1 KiB truly-random (encrypted) data averages 7.81 and reads BELOW 7.85 ~100% of the
    time, so a small block/probe size would silently misclassify encrypted data as intact.
    Measured on the Makop/.ndm448 samples: a 256-byte ciphertext window reads
    ~7.18. This shifts the threshold by the same finite-sample deficit so the margin below
    'looks random' is preserved at any block size, never rising above the base 7.85.

    The deficit model diverges for tiny blocks (it exceeds 8 bits and the threshold would go
    negative, flagging everything), so the effective block is floored at MIN_CLASSIFY_BLOCK.
    """
    n = max(block_size, MIN_CLASSIFY_BLOCK)
    shift = _entropy_deficit(n) - _entropy_deficit(THRESHOLD_REF_BLOCK)
    return min(ENCRYPTED_THRESHOLD, ENCRYPTED_THRESHOLD - shift)


class Cancelled(Exception):
    """Raised internally when a caller-supplied cancel check trips."""


@dataclass
class ScanReport:
    mode: str
    size: int
    pattern: str
    encrypted_bytes: int = 0
    boundary_offset: Optional[int] = None
    encrypted_pct: float = 0.0
    note: str = ""
    block_size: Optional[int] = None
    total_blocks: Optional[int] = None
    high_entropy_blocks: Optional[int] = None
    zero_blocks: Optional[int] = None
    runs: Optional[int] = None
    run_length_sample: list = field(default_factory=list)
    coarse_samples: list = field(default_factory=list)
    isolated_high_entropy_offsets: list = field(default_factory=list)
    family: Optional[dict] = None  # ransomware family identification, if any (see signatures)
    formats: list = field(default_factory=list)  # container/format findings in intact region

    @property
    def recoverable_bytes(self) -> int:
        return max(self.size - self.encrypted_bytes, 0)

    @property
    def recoverable_pct(self) -> float:
        return round(100 * self.recoverable_bytes / self.size, 4) if self.size else 0.0

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "size": self.size,
            "pattern": self.pattern,
            "encrypted_bytes": self.encrypted_bytes,
            "boundary_offset": self.boundary_offset,
            "encrypted_pct": self.encrypted_pct,
            "recoverable_bytes": self.recoverable_bytes,
            "recoverable_pct": self.recoverable_pct,
            "note": self.note,
            "block_size": self.block_size,
            "total_blocks": self.total_blocks,
            "high_entropy_blocks": self.high_entropy_blocks,
            "zero_blocks": self.zero_blocks,
            "runs": self.runs,
            "run_length_sample": self.run_length_sample,
            "isolated_high_entropy_offsets": self.isolated_high_entropy_offsets,
            "family": self.family,
            "formats": self.formats,
        }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_all_zero(b: bytes) -> bool:
    return len(b) > 0 and b.count(0) == len(b)


def _classify_sample(b: bytes) -> str:
    if _is_all_zero(b):
        return "zero"
    if len(b) < MIN_CLASSIFY_BLOCK:
        # Too few bytes to distinguish random from structured -- don't risk a false
        # "encrypted" on a runt tail read; treat as intact (conservative for recovery).
        return "intact"
    e = shannon_entropy(b)
    if e <= encrypted_threshold(len(b)):
        return "intact"
    # High entropy: encrypted OR compressed. The chi-square uniformity test tells them
    # apart -- encryption is statistically random, most compressed content is not. If the
    # block is clearly non-random (structured), it's recoverable compressed data, not part
    # of an encrypted region, so classify it intact. This never reclassifies genuinely
    # random data (encryption's chi-square stays near 255, well under the ceiling).
    if _stats_mod.looks_compressed(_stats_mod.chi_square_uniform(b), len(b)):
        return "intact"
    return "encrypted"


def _check_cancel(cancel_check):
    if cancel_check is not None and cancel_check():
        raise Cancelled()


# ---------------------------------------------------------------- boundary (front-only) mode

def _coarse_scan(src, sample_size: int, progress: ProgressFn, cancel_check):
    size = src.size
    step = max(sample_size, size // COARSE_STEP_DIVISOR)
    rows = []
    off = 0
    while off < size:
        _check_cancel(cancel_check)
        b = src.read_at(off, sample_size)
        if not b:
            break
        rows.append((off, round(shannon_entropy(b), 3), _classify_sample(b)))
        off += step
        if progress:
            progress(min(off / size, 1.0) * 0.5, "Coarse scan")
    return rows, size


def _refine_boundary(src, lo: int, hi: int, sample_size: int, precision: int,
                      progress: ProgressFn, cancel_check) -> int:
    """Binary-search between an offset known to be encrypted (lo) and one known to be
    intact (hi). Reads a probe no larger than `precision` at each midpoint -- using
    the full (much larger) `sample_size` here would make the probe window straddle
    the true boundary once hi-lo shrinks below it, mixing encrypted and intact bytes
    into one diluted entropy reading and biasing the result away from the real edge."""
    span = max(hi - lo, 1)
    probe_size = min(sample_size, precision)
    while hi - lo > precision:
        _check_cancel(cancel_check)
        mid = (lo + hi) // 2
        b = src.read_at(mid, probe_size)
        if _classify_sample(b) == "encrypted":
            lo = mid
        else:
            hi = mid
        if progress:
            done = 1.0 - (hi - lo) / span
            progress(0.5 + min(done, 1.0) * 0.4, "Refining boundary")
    return hi


def _max_encrypted_run(rows, start_idx: int) -> int:
    """Longest run of consecutive coarse samples classified 'encrypted', looking only at
    rows[start_idx:] (i.e. past the contiguous front region). Used to tell a real second
    encrypted region (a run) from scattered isolated high-entropy points (no run)."""
    best = cur = 0
    for r in rows[start_idx:]:
        if r[2] == "encrypted":
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def boundary_scan(path: str, sample_size: int = 65536, progress: ProgressFn = None,
                   cancel_check=None) -> ScanReport:
    """Find the single front-encrypted boundary, assuming (and then checking) that the
    rest of the file is intact.

    The boundary bracket MUST come from a contiguous run of encrypted samples starting
    at offset 0 -- never from "the last coarse sample classified as encrypted anywhere
    in the file". That earlier approach was tried and produced a real false positive: on
    a 26 GB disk image, two isolated, unrelated high-entropy points elsewhere in the file
    (dense filesystem content with nothing to do with the ransomware) got picked as the
    anchor and inflated the reported boundary from a true ~1 MB to a false ~312 MB. Any
    high-entropy samples found outside the contiguous front run are real, but they are
    reported separately as `isolated_high_entropy_offsets` for the caller to verify on
    their own terms, not folded into the boundary.
    """
    with open_source(path) as src:
        return _boundary_scan(src, sample_size, progress, cancel_check)


def _boundary_scan(src, sample_size: int, progress: ProgressFn, cancel_check) -> ScanReport:
    rows, size = _coarse_scan(src, sample_size, progress, cancel_check)

    any_encrypted = any(r[2] == "encrypted" for r in rows)
    if not any_encrypted:
        return ScanReport(
            mode="boundary", size=size, pattern="fully-intact",
            encrypted_bytes=0, boundary_offset=0,
            note="No encrypted samples found at coarse resolution. Re-run with a full "
                 "scan before concluding the file is untouched -- a short encrypted "
                 "region can still hide between coarse sample points.",
            coarse_samples=rows,
        )

    if not rows or rows[0][2] != "encrypted":
        return ScanReport(
            mode="boundary", size=size, pattern="non-contiguous",
            note="High-entropy samples exist but the file does not start encrypted, so "
                 "this isn't a simple front-only pattern. Escalate to a full scan to map "
                 "where the encryption actually is.",
            coarse_samples=rows,
            isolated_high_entropy_offsets=[r[0] for r in rows if r[2] == "encrypted"],
        )

    # Walk the contiguous encrypted prefix from offset 0 -- this, and only this, is a
    # valid boundary bracket.
    idx = 0
    while idx < len(rows) and rows[idx][2] == "encrypted":
        idx += 1
    if idx >= len(rows):
        return ScanReport(
            mode="boundary", size=size, pattern="fully-encrypted",
            encrypted_bytes=size, boundary_offset=size, encrypted_pct=100.0,
            note="All coarse samples read as encrypted. Likely a full-file-encryption "
                 "variant; the partial-recovery technique does not apply here.",
            coarse_samples=rows,
        )

    last_enc = rows[idx - 1][0]
    boundary_bracket_hi = rows[idx][0]
    isolated = [r[0] for r in rows[idx + 1:] if r[2] == "encrypted"]

    if rows[idx][2] != "intact":
        # The sample right after the contiguous run is "zero" (unallocated), not a clean
        # intact reading -- find the first genuinely intact sample to bracket the refine.
        first_intact_after = min((r[0] for r in rows[idx:] if r[2] == "intact"), default=None)
        if first_intact_after is None:
            return ScanReport(
                mode="boundary", size=size, pattern="non-contiguous",
                note="Encrypted run at the front is followed by unallocated/ambiguous "
                     "space with no clean intact sample to bracket against. Escalate to "
                     "a full scan.",
                coarse_samples=rows, isolated_high_entropy_offsets=isolated,
            )
        boundary_bracket_hi = first_intact_after

    boundary = _refine_boundary(src, last_enc, boundary_bracket_hi, sample_size,
                                 REFINE_PRECISION, progress, cancel_check)

    check_points = min(20, max(1, (size - boundary) // max(sample_size, 1)))
    step = max(sample_size, (size - boundary) // max(check_points, 1))
    suspect = []
    off = boundary
    n = 0
    while off < size:
        _check_cancel(cancel_check)
        b = src.read_at(off, sample_size)
        if not b:
            break
        if _classify_sample(b) == "encrypted":
            suspect.append(off)
        off += step
        n += 1
        if progress:
            progress(0.9 + min(n / max(check_points, 1), 1.0) * 0.1, "Verifying")

    all_suspect = sorted(set(suspect) | {o for o in isolated if o > boundary})

    # Decide whether the post-boundary high-entropy is a genuine second encrypted region
    # (escalate to a full map) or just scattered benign content (do not). A single isolated
    # sample must never force a full scan -- see the ESCALATE_* constants for why.
    coarse_step = (rows[1][0] - rows[0][0]) if len(rows) > 1 else size
    max_run_bytes = _max_encrypted_run(rows, idx) * coarse_step
    suspect_frac = len(suspect) / max(check_points, 1)
    genuine_second_region = (
        suspect_frac >= ESCALATE_SUSPECT_FRACTION
        or max_run_bytes >= ESCALATE_RUN_FRACTION * size
    )
    pattern = "non-contiguous" if genuine_second_region else "front-only"

    if pattern == "front-only":
        note = (
            f"Front-only encryption confirmed: only the first {boundary:,} bytes "
            f"({100*boundary/size:.4f}% of the file) are encrypted. Everything from "
            f"offset {boundary:,} onward reads as intact across {check_points} spot-checks."
        )
        if all_suspect:
            note += (
                f" {len(all_suspect)} isolated high-entropy sample(s) exist past the boundary "
                "but form no large contiguous run and stayed a small fraction of the "
                "spot-checks -- consistent with benign dense content (database, compressed, "
                "or media blocks), not a second encrypted region. They are listed in "
                "isolated_high_entropy_offsets; re-run with --full to map them precisely."
            )
    else:
        note = (
            "A substantial or contiguous high-entropy region exists past the front boundary "
            "-- the encryption may not be confined to the front. Escalating to a full scan "
            "to map exactly where it is."
        )

    if progress:
        progress(1.0, "Done")

    return ScanReport(
        mode="boundary", size=size, pattern=pattern,
        encrypted_bytes=boundary, boundary_offset=boundary,
        encrypted_pct=round(100 * boundary / size, 4),
        note=note, coarse_samples=rows,
        isolated_high_entropy_offsets=all_suspect,
    )


# ---------------------------------------------------------------- full block-scan mode

def _to_runs(block_indices):
    if not block_indices:
        return []
    runs = []
    start = prev = block_indices[0]
    for i in block_indices[1:]:
        if i != prev + 1:
            runs.append((start, prev - start + 1))
            start = i
        prev = i
    runs.append((start, prev - start + 1))
    return runs


def _regularity_verdict(runs, chi2_by_block=None, chi2_usable=False, magics_by_block=None):
    """The key discriminator among a set of runs assumed to be of comparable size: real
    intermittent/periodic encryption produces regular, similarly-sized runs at roughly
    regular spacing. Scattered high-entropy content that is just compressed/binary data
    (LOB blobs, images, etc.) produces short, irregular runs at irregular spacing.

    When a run set looks periodic (an encryption verdict), the chi-square uniformity test
    is used as a tie-breaker: if the blocks are statistically non-random they are compressed
    content that merely happens to be regularly spaced, so the verdict is corrected to
    compressed-benign rather than a false periodic-encryption call."""
    lengths = [r[1] for r in runs]
    starts = [r[0] for r in runs]
    gaps = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)] if len(starts) > 1 else []

    avg_len = sum(lengths) / len(lengths)
    len_spread = (max(lengths) - min(lengths)) if lengths else 0
    gap_spread = (max(gaps) - min(gaps)) if gaps else 0
    avg_gap = (sum(gaps) / len(gaps)) if gaps else 0

    if gaps and avg_gap > 0 and (len_spread / max(avg_len, 1)) < 0.3 and (gap_spread / avg_gap) < 0.3:
        comp, why = _run_is_compressed(runs, chi2_by_block, magics_by_block, chi2_usable)
        if comp:
            return ("compressed-benign",
                    f"{len(runs)} regularly-spaced high-entropy runs, but their bytes {why} "
                    f"-- regularly-laid-out compressed/binary content, not encryption.")
        return ("periodic-intermittent",
                f"{len(runs)} runs of consistent size (~{avg_len:.0f} blocks) at consistent "
                f"spacing (~{avg_gap:.0f} blocks): looks like deliberate intermittent "
                f"encryption throughout the file, not benign content.")

    return ("scattered-benign",
            f"{len(runs)} short runs (avg {avg_len:.1f} blocks) at irregular spacing: "
            f"consistent with ordinary compressed/binary content (e.g. LOB data, images), "
            f"not an encryption pattern. Cross-check with a format-aware validator before "
            f"trusting this for a structured file like a database.")


# Patterns whose high-entropy blocks are recoverable content, not ciphertext.
_BENIGN_PATTERNS = {"fully-intact", "scattered-benign", "compressed-benign"}


def _run_blocks_mean_chi2(runs, chi2_by_block):
    """Mean chi-square across every block in the given runs, or None if unavailable."""
    if not chi2_by_block:
        return None
    vals = []
    for start, length in runs:
        for i in range(start, start + length):
            if i in chi2_by_block:
                vals.append(chi2_by_block[i])
    return (sum(vals) / len(vals)) if vals else None


# Reliable compression-stream headers past which a run is structurally compressed content, not
# ciphertext. A handful is decisive: the magics counted are 4+ bytes (see
# stats._COMPRESSION_MAGICS), so ~4 essentially cannot arise in random/encrypted data, while a
# Docker image layer or archive carries thousands.
COMPRESSION_MAGIC_MIN = 4


def _run_reliable_magics(runs, magics_by_block):
    """Total reliable compression-stream headers across the given runs' blocks, or None."""
    if not magics_by_block:
        return None
    return sum(magics_by_block.get(i, 0)
               for start, length in runs for i in range(start, start + length))


def _run_is_compressed(runs, chi2_by_block, magics_by_block, chi2_usable):
    """(is_compressed, reason_fragment). Two independent signals show a high-entropy run is
    recoverable compressed content rather than ciphertext: the chi-square uniformity test failing
    (statistical), and reliable compression-stream magics being present (structural). The
    structural signal catches data compressed so tightly it is statistically uniform -- Docker
    image layers, xz/zstd blobs -- which fools entropy AND chi-square. Encryption satisfies
    neither test, so a genuine encryption verdict is never downgraded."""
    if chi2_usable:
        mean_chi2 = _run_blocks_mean_chi2(runs, chi2_by_block)
        if mean_chi2 is not None and _stats_mod.run_looks_compressed(mean_chi2):
            return True, f"fail the uniform-randomness test (mean chi-square {mean_chi2:.0f} >> ~255)"
    magics = _run_reliable_magics(runs, magics_by_block)
    if magics is not None and magics >= COMPRESSION_MAGIC_MIN:
        return True, (f"carry {magics:,} compression-stream headers (gzip/xz/zstd/zip) that "
                      f"ciphertext never contains")
    return False, ""


def _classify_runs(runs, nblocks, chi2_by_block=None, block_size=8192, magics_by_block=None):
    """Split off any dominant, size-outlier run(s) as candidate contiguous-encryption
    regions before judging periodic-vs-scattered on what's left. Without this split, a
    single large front-encrypted run sitting alongside small, irregular high-entropy
    noise elsewhere in the file (e.g. dense filesystem content) drags the size variance
    up enough that the whole file reads as 'irregular' and gets misclassified
    scattered-benign, even though a large contiguous chunk really is encrypted.

    The chi-square uniformity test (when block stats are available and the block size is
    adequate) is applied as a precision-preserving override: if the high-entropy blocks
    are statistically NON-random, they are compressed content, not encryption, so an
    encryption verdict is downgraded to 'compressed-benign'. Genuinely random/encrypted
    blocks (chi-square ~255) are never touched by this."""
    if not runs:
        return "fully-intact", "No high-entropy blocks found."

    chi2_usable = chi2_by_block and block_size >= _stats_mod.MIN_CHI2_BLOCK

    if len(runs) == 1 and runs[0][1] > nblocks * 0.5:
        comp, why = _run_is_compressed(runs, chi2_by_block, magics_by_block, chi2_usable)
        if comp:
            return ("compressed-benign",
                    f"A single high-entropy run covers most of the file, but its bytes {why} "
                    f"-- one large block of compressed/binary content, not encryption.")
        return "fully-encrypted", "A single run covering most of the file: likely fully encrypted."

    lengths = [r[1] for r in runs]
    sorted_lengths = sorted(lengths)
    median_len = sorted_lengths[len(sorted_lengths) // 2]
    dominant_threshold = max(median_len * 5, nblocks * 0.02)

    dominant = [r for r in runs if r[1] >= dominant_threshold]
    rest = [r for r in runs if r not in dominant]

    if dominant and rest:
        dominant_bytes = sum(r[1] for r in dominant)
        # A dominant run is real contiguous encryption only if it's statistically random AND free
        # of compression-stream structure; otherwise it's a large compressed region, not a front.
        comp, why = _run_is_compressed(dominant, chi2_by_block, magics_by_block, chi2_usable)
        if comp:
            return ("compressed-benign",
                    f"The dominant high-entropy run(s) covering {dominant_bytes} block(s) {why} "
                    f"-- large compressed/binary content, not an encrypted region.")
        rest_pattern, rest_note = _regularity_verdict(rest, chi2_by_block, chi2_usable, magics_by_block)
        starts_at_front = dominant[0][0] == 0
        pattern = "front-only" if (starts_at_front and len(dominant) == 1) else "mixed"
        note = (
            f"{len(dominant)} dominant run(s) covering {dominant_bytes} block(s) stand out as "
            f"outliers ({dominant_threshold:.0f}+ blocks vs a {median_len}-block median) and "
            "look like genuine contiguous encryption -- e.g. a front-encrypted region. "
            f"The remaining {len(rest)} run(s) were judged separately: {rest_note}"
        )
        return pattern, note

    return _regularity_verdict(runs, chi2_by_block, chi2_usable, magics_by_block)


def _chunk_stats(data: bytes, block_size: int):
    """Per-block (entropy, is_all_zero, chi_square) for a chunk. Entropy and the
    chi-square uniformity statistic both come from the SAME byte-count bincount, so the
    randomness test is nearly free on top of the entropy pass. Vectorised with numpy.
    chi_square ~255 means uniform-random (encrypted); higher means structured (compressed)."""
    n = len(data) // block_size
    expected = block_size / 256.0
    if _np is None:
        out = []
        for j in range(n):
            b = data[j * block_size:(j + 1) * block_size]
            out.append((shannon_entropy(b), _is_all_zero(b),
                        _stats_mod.chi_square_uniform(b)))
        return out
    arr = _np.frombuffer(data, dtype=_np.uint8)[:n * block_size].reshape(n, block_size)
    offsets = (_np.arange(n, dtype=_np.int64) * 256)[:, None]
    counts = _np.bincount((arr.astype(_np.int64) + offsets).ravel(),
                          minlength=n * 256).reshape(n, 256)
    p = counts / float(block_size)
    logp = _np.zeros_like(p)
    mask = p > 0
    logp[mask] = _np.log2(p[mask])
    ent = -(p * logp).sum(axis=1)
    zeros = counts[:, 0] == block_size
    chi2 = ((counts - expected) ** 2 / expected).sum(axis=1)
    return list(zip(ent.tolist(), zeros.tolist(), chi2.tolist()))


def _iter_blocks(src, block_size: int, nblocks: int, progress: ProgressFn, cancel_check,
                  label: str):
    """Yield (block_index, block_bytes, entropy, is_all_zero, chi_square), reading the
    input in FULL_SCAN_CHUNK-sized sequential reads rather than one read() per block."""
    blocks_per_chunk = max(FULL_SCAN_CHUNK // block_size, 1)
    for chunk_start in range(0, nblocks, blocks_per_chunk):
        _check_cancel(cancel_check)
        if progress:
            progress(chunk_start / max(nblocks, 1), label)
        count = min(blocks_per_chunk, nblocks - chunk_start)
        data = src.read_at(chunk_start * block_size, count * block_size)
        for j, (ent, zero, chi2) in enumerate(_chunk_stats(data, block_size)):
            yield chunk_start + j, data[j * block_size:(j + 1) * block_size], ent, zero, chi2


def full_scan(path: str, block_size: int = 8192, progress: ProgressFn = None,
              cancel_check=None) -> ScanReport:
    """Scan every block. Slower but the only reliable way to detect encryption
    scattered throughout a file rather than confined to the front."""
    with open_source(path) as src:
        size = src.size
        nblocks = size // block_size
        threshold = encrypted_threshold(block_size)
        high_entropy_blocks = []
        chi2_by_block = {}
        magics_by_block = {}
        zero_blocks = 0

        for i, _b, ent, zero, chi2 in _iter_blocks(src, block_size, nblocks, progress,
                                                    cancel_check, "Full scan"):
            if zero:
                zero_blocks += 1
                continue
            if ent > threshold:
                high_entropy_blocks.append(i)
                chi2_by_block[i] = chi2
                magics_by_block[i] = _stats_mod.reliable_compression_magic_count(_b)

    runs = _to_runs(high_entropy_blocks)
    pattern, note = _classify_runs(runs, nblocks, chi2_by_block, block_size, magics_by_block)

    if progress:
        progress(1.0, "Done")

    # For benign patterns the high-entropy blocks are recoverable content, not ciphertext,
    # so they must not be counted as encrypted -- otherwise the report contradicts itself
    # ("compressed-benign, 40% encrypted"). Only genuinely-encrypted patterns count bytes.
    encrypted_blocks = 0 if pattern in _BENIGN_PATTERNS else len(high_entropy_blocks)
    return ScanReport(
        mode="full", size=size, pattern=pattern,
        block_size=block_size, total_blocks=nblocks, zero_blocks=zero_blocks,
        high_entropy_blocks=len(high_entropy_blocks),
        encrypted_bytes=encrypted_blocks * block_size,
        encrypted_pct=round(100 * encrypted_blocks / max(nblocks, 1), 4),
        runs=len(runs), run_length_sample=runs[:10],
        note=note,
    )


def scan(path: str, full: bool = False, sample_size: int = 65536, block_size: int = 8192,
          progress: ProgressFn = None, cancel_check=None, boundary_only: bool = False) -> ScanReport:
    """Adaptive top-level entry point: fingerprint the file against known ransomware
    families first (cheap: a filename + trailing-bytes check), then try boundary search
    (cheap even on huge files) and escalate to a full block scan if the pattern isn't a
    single contiguous front region, or if the caller asks for --full explicitly.

    `boundary_only=True` accepts the fast boundary result and skips the full-scan
    escalation even when the pattern is non-contiguous -- for when the boundary is all the
    caller needs and a full O(size) read of a huge slow disk is not worth the wait."""
    ident = _identify(path)

    if full:
        report = full_scan(path, block_size, progress, cancel_check)
        report.family = ident
        _apply_compressed_container_override(path, report)
        _apply_family_expectations(report, ident)
        _detect_formats(path, report)
        return report

    report = boundary_scan(path, sample_size, progress, cancel_check)
    if report.pattern == "non-contiguous" and not boundary_only:
        report = full_scan(path, block_size, progress, cancel_check)
    report.family = ident
    _apply_compressed_container_override(path, report)
    _apply_family_expectations(report, ident)
    _detect_formats(path, report)
    return report


# Patterns that assert some region is encrypted -- candidates for the container override.
_ENCRYPTION_PATTERNS = {"fully-encrypted", "front-only", "periodic-intermittent", "mixed"}


def _apply_compressed_container_override(path: str, report: ScanReport) -> None:
    """If the file starts with a valid compressed-archive/stream header, its high entropy
    is compression, not encryption -- correct an encryption verdict to compressed-benign.

    This is the rigorous fallback for statistically-uniform compressors (LZMA/xz) that the
    chi-square test can't flag. A present header also means the front wasn't encrypted
    (ransomware encrypting the front would have destroyed it), so it's safe to mark the
    whole file recoverable. Only fires on an encryption verdict."""
    if report.pattern not in _ENCRYPTION_PATTERNS:
        return
    try:
        from .formats import compressed_container_at
        container = compressed_container_at(path, 0)
    except Exception:  # noqa: BLE001
        container = None
    if not container:
        return
    report.pattern = "compressed-benign"
    report.encrypted_bytes = 0
    report.encrypted_pct = 0.0
    report.boundary_offset = None
    report.note = (
        f"The file begins with a valid {container} header, so its high-entropy content is "
        f"compression, not encryption -- fully recoverable. (This header also could not "
        f"survive front-encryption, confirming the front is intact.) The entropy scan "
        f"alone read it as encrypted because {container}-class compressed output is "
        f"statistically indistinguishable from ciphertext by entropy or chi-square."
    )


def _detect_formats(path: str, report: ScanReport) -> None:
    """Best-effort container/format detection on the recoverable region; never fatal.
    Skipped when nothing is recoverable (fully encrypted)."""
    if report.pattern == "fully-encrypted":
        return
    try:
        from .formats import detect
        intact_start = report.boundary_offset or 0
        report.formats = detect(path, intact_start=intact_start, intact_end=report.size)
    except Exception:  # noqa: BLE001 -- advisory only
        report.formats = []


def _apply_family_expectations(report: ScanReport, ident) -> None:
    """Advisory-only cross-check of a detected front-only boundary against what the
    identified family is known to do. Never changes the recovery numbers -- it only
    appends a caveat, because a boundary well beyond the family's intended extent
    suggests either a different variant or a mis-detected boundary worth a second look."""
    if not ident or report.pattern != "front-only":
        return
    frac = ident.get("typical_max_encrypted_fraction")
    if frac and report.size and report.encrypted_bytes > report.size * frac:
        report.note += (
            f" Advisory: the encrypted front ({report.encrypted_pct:.2f}%) exceeds the "
            f"~{frac*100:.0f}% this family ({ident['family']}) typically encrypts. "
            f"Confirm the boundary before relying on the recovery estimate -- this may be "
            f"a different variant or a mis-detected boundary."
        )


def _identify(path: str):
    """Best-effort family fingerprint; never fails a scan if signatures can't be read."""
    try:
        from .signatures import identify_path
        ident = identify_path(path)
        return ident.to_dict() if ident.identified else None
    except Exception:  # noqa: BLE001 -- identification is advisory, never fatal
        return None


# ---------------------------------------------------------------- extraction

def extract_intact_ranges(path: str, report: ScanReport, out_path: str,
                           progress: ProgressFn = None, cancel_check=None,
                           chunk_size: int = 1024 * 1024) -> int:
    """Write the identified intact byte range(s) of `path` to `out_path`.

    boundary mode: everything from boundary_offset to end of file.
    full mode: every block NOT flagged high-entropy, written contiguously in
    original order (a raw carve, not a filesystem-aware reconstruction -- for
    structure-aware extraction from virtual disks, use recover_files/--recover-files).

    Returns the number of bytes written. Never modifies the input.
    """
    size = report.size
    written = 0

    if report.mode == "boundary":
        start = report.boundary_offset or 0
        total = max(size - start, 0)
        with open_source(path) as src, open(out_path, "wb") as dst:
            off = start
            while off < size:
                _check_cancel(cancel_check)
                b = src.read_at(off, min(chunk_size, size - off))
                if not b:
                    break
                dst.write(b)
                written += len(b)
                off += len(b)
                if progress:
                    progress(written / max(total, 1), "Extracting")
        if progress:
            progress(1.0, "Done")
        return written

    # full mode: skip only the blocks flagged as high-entropy; keep block ordering.
    # ScanReport only retains a 10-run sample for display, so re-derive the
    # per-block entropy classification here rather than trusting that sample.
    block_size = report.block_size or 8192
    total_blocks = report.total_blocks or (size // block_size)
    threshold = encrypted_threshold(block_size)
    with open_source(path) as src, open(out_path, "wb") as dst:
        for _, b, ent, zero, chi2 in _iter_blocks(src, block_size, total_blocks, progress,
                                                   cancel_check, "Extracting"):
            # Keep a block if it's zero, low-entropy, OR high-entropy but statistically
            # non-random -- the last case is recoverable compressed content that the old
            # entropy-only rule would have wrongly discarded as "encrypted".
            keep = (zero or ent <= threshold
                    or _stats_mod.looks_compressed(chi2, block_size))
            if keep:
                dst.write(b)
                written += len(b)
    if progress:
        progress(1.0, "Done")
    return written


def ntfs_volume_length(path: str, offset: int) -> Optional[int]:
    """Byte length of the NTFS volume whose boot sector sits at `offset`, or None.

    Read from the boot sector itself: bytes-per-sector (uint16 at +0x0B) times total
    sectors (uint64 at +0x28), plus one sector for the backup boot sector NTFS keeps
    just past the end of the volume. Returns None when the fields are implausible,
    so callers fall back to copying through to end of input."""
    try:
        with open_source(path) as src:
            bs = src.read_at(offset, 512)
        if len(bs) < 512 or bs[3:11] != b"NTFS    ":
            return None
        bps = int.from_bytes(bs[0x0B:0x0D], "little")
        total_sectors = int.from_bytes(bs[0x28:0x30], "little")
        if bps not in (256, 512, 1024, 2048, 4096) or not 0 < total_sectors < 2**48:
            return None
        return (total_sectors + 1) * bps
    except (OSError, ValueError):
        return None


def extract_range(path: str, start: int, length: Optional[int], out_path: str,
                  progress: ProgressFn = None, cancel_check=None,
                  chunk_size: int = 1024 * 1024) -> int:
    """Copy `length` bytes of `path` starting at `start` into `out_path` (read-only on
    the input). `length=None` copies through to end of input. Used to cut a detected
    NTFS volume out of a disk image as a standalone partition image that tools like
    7-Zip and forensic suites can open directly. Returns bytes written."""
    with open_source(path) as src:
        end = src.size if length is None else min(start + length, src.size)
        total = max(end - start, 1)
        written = 0
        with open(out_path, "wb") as dst:
            off = start
            while off < end:
                _check_cancel(cancel_check)
                b = src.read_at(off, min(chunk_size, end - off))
                if not b:
                    break
                dst.write(b)
                written += len(b)
                off += len(b)
                if progress:
                    progress(written / total, "Extracting")
    if progress:
        progress(1.0, "Done")
    return written
