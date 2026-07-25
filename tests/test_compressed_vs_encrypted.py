"""End-to-end: chi-square lets the engine tell compressed content from encryption.

These are the cases that entropy alone gets wrong. Encrypted = os.urandom; compressed =
real zlib/DEFLATE output.
"""
import os
import random
import zlib

from rprt import engine


def _text(n, seed):
    rng = random.Random(seed)
    words = [bytes(rng.randrange(97, 123) for _ in range(rng.randint(2, 9))) for _ in range(4000)]
    out = bytearray()
    while len(out) < n:
        out += rng.choice(words) + b" "
    return bytes(out[:n])


def _deflate(n, seed):
    return zlib.compress(_text(n * 4, seed), 9)[:n]


def test_boundary_scan_does_not_flag_compressed_front(tmp_path):
    # a big DEFLATE region at the front, then text. Entropy alone would call the front
    # "encrypted"; chi-square recognises it as compressed -> not a front-only boundary.
    comp = b"".join(_deflate(65536, seed=i) for i in range(48))   # ~3 MB compressed
    body = (b"plain readable text " * 200000)
    p = tmp_path / "compressed_front.bin"
    p.write_bytes(comp + body)
    report = engine.boundary_scan(str(p))
    # the compressed front must NOT be reported as an encrypted front region
    assert report.pattern in ("fully-intact", "non-contiguous")
    assert report.encrypted_bytes == 0 or report.pattern != "front-only"


def test_full_scan_large_compressed_region_is_benign(tmp_path):
    # one large DEFLATE region dominating the file -> compressed-benign, not fully/front
    comp = b"".join(_deflate(65536, seed=i) for i in range(200))   # ~13 MB
    p = tmp_path / "big_compressed.bin"
    p.write_bytes(comp)
    report = engine.full_scan(str(p), block_size=8192)
    assert report.pattern == "compressed-benign"
    # benign -> recoverable, not counted as encrypted
    assert report.encrypted_bytes == 0
    assert report.recoverable_pct == 100.0


def test_encrypted_region_still_detected(tmp_path):
    # control: genuine random front is still detected as front-only encryption
    enc = os.urandom(2 * 1024 * 1024)
    body = (b"plain readable text " * 400000)[:6 * 1024 * 1024]
    p = tmp_path / "enc_front.bin"
    p.write_bytes(enc + body)
    report = engine.scan(str(p))
    assert report.pattern == "front-only"
    assert abs(report.boundary_offset - 2 * 1024 * 1024) <= engine.REFINE_PRECISION


def test_periodic_compressed_not_called_encryption(tmp_path):
    # regularly-spaced DEFLATE blocks: regular enough to look periodic, but chi-square
    # corrects the verdict to compressed-benign instead of periodic-intermittent.
    block = 8192
    pages = []
    i = 0
    while i < 300:
        if i % 10 == 0:
            for _ in range(2):
                pages.append(_deflate(block, seed=1000 + i)); i += 1
        else:
            pages.append((b"text data " * 900)[:block]); i += 1
    p = tmp_path / "periodic_compressed.bin"
    p.write_bytes(b"".join(pages)[:300 * block])
    report = engine.full_scan(str(p), block_size=block)
    assert report.pattern == "compressed-benign"


def test_extraction_keeps_compressed_blocks(tmp_path):
    # full-mode extraction must PRESERVE compressed blocks (recoverable), not drop them
    block = 8192
    comp_blocks = [_deflate(block, seed=i) for i in range(20)]
    text_blocks = [(b"readable text " * 700)[:block] for _ in range(20)]
    data = b"".join(comp_blocks + text_blocks)
    p = tmp_path / "mix.bin"
    p.write_bytes(data)
    report = engine.full_scan(str(p), block_size=block)

    out = str(tmp_path / "recovered.bin")
    written = engine.extract_intact_ranges(str(p), report, out)
    # nearly everything is recoverable (compressed + text), so almost nothing is dropped
    assert written >= len(data) * 0.95
