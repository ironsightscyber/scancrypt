"""Format-context override: a compressed-archive header proves compression, not encryption.

This handles the case the chi-square test provably cannot: LZMA/xz output is statistically
uniform (chi-square ~255), indistinguishable from ciphertext by distribution -- but a valid
xz/7z/gzip/zip header at the file start settles it structurally. Uses REAL compressed
streams (Python's lzma/gzip/bz2/zipfile).
"""
import bz2
import gzip
import io
import lzma
import os
import zipfile

from rprt import engine, formats


def _xz_blob(nbytes):
    # compressing random data yields a large, statistically-uniform, valid xz stream.
    # Seeded (not os.urandom) so the content is deterministic: fresh random each run made this
    # occasionally land on a borderline blob and flake under some test orderings.
    import random
    return lzma.compress(random.Random(20260722).randbytes(nbytes))


def test_compressed_container_at_detects_real_headers(tmp_path):
    cases = {
        "x.xz": lzma.compress(b"hello world" * 100),
        "x.gz": gzip.compress(b"hello world" * 100),
        "x.bz2": bz2.compress(b"hello world" * 100),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"hello" * 100)
    cases["x.zip"] = buf.getvalue()

    for name, data in cases.items():
        p = tmp_path / name
        p.write_bytes(data)
        assert formats.compressed_container_at(str(p), 0) is not None, name


def test_compressed_container_at_none_on_random(tmp_path):
    p = tmp_path / "r.bin"
    p.write_bytes(os.urandom(4096))
    assert formats.compressed_container_at(str(p)) is None


def test_large_xz_file_classified_compressed_not_encrypted(tmp_path):
    # ~4 MB xz stream: entropy AND chi-square read it as encrypted; the xz header saves it
    blob = _xz_blob(4 * 1024 * 1024)
    p = tmp_path / "backup.xz"
    p.write_bytes(blob)

    # sanity: without the header context this looks encrypted
    raw = engine.boundary_scan(str(p))
    assert raw.pattern in ("fully-encrypted", "front-only")

    # the full adaptive scan applies the container override
    report = engine.scan(str(p))
    assert report.pattern == "compressed-benign"
    assert report.encrypted_bytes == 0
    assert report.recoverable_pct == 100.0
    assert "xz" in report.note.lower()


def test_override_does_not_fire_on_genuine_encryption(tmp_path):
    # random front + text body, no container header -> stays front-only encryption
    enc = os.urandom(2 * 1024 * 1024)
    body = (b"plain readable text " * 400000)[:6 * 1024 * 1024]
    p = tmp_path / "enc.bin"
    p.write_bytes(enc + body)
    report = engine.scan(str(p))
    assert report.pattern == "front-only"
    assert report.boundary_offset is not None


def test_override_does_not_touch_intact_files(tmp_path):
    p = tmp_path / "t.txt"
    p.write_bytes((b"just some readable text. " * 100000))
    report = engine.scan(str(p))
    assert report.pattern == "fully-intact"   # not an encryption verdict; override no-ops


def test_synthetic_7z_header_overrides_fully_encrypted(tmp_path):
    # 7z magic then uniform random body: without the header this is "fully-encrypted"
    body = os.urandom(3 * 1024 * 1024)
    p = tmp_path / "a.7z"
    p.write_bytes(b"7z\xbc\xaf\x27\x1c" + body)
    report = engine.scan(str(p))
    assert report.pattern == "compressed-benign"
    assert report.recoverable_pct == 100.0
