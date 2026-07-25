"""Container/format detection on the intact region."""
import random

from rprt import engine, formats


def _rand(n, seed):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def test_header_signature_zip(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 1000)
    found = formats.detect(str(p))
    assert any("ZIP" in f["name"] for f in found)
    assert found[0]["where"] == "header"
    assert found[0]["offset"] == 0


def test_header_signature_at_offset(tmp_path):
    # ESE/EDB magic sits at offset 4
    p = tmp_path / "ntds.dit"
    p.write_bytes(b"\x00\x00\x00\x00" + b"\xef\xcd\xab\x89" + b"\x00" * 500)
    found = formats.detect(str(p))
    assert any("ESE" in f["name"] or "EDB" in f["name"] for f in found)


def test_interior_ntfs_boot_sector_found(tmp_path):
    # Simulate a disk image whose front is encrypted, with an intact NTFS volume that
    # starts partway in: "NTFS    " magic at byte 3 of a 512-aligned sector.
    volume_off = 512 * 20         # NTFS volume starts at a sector boundary within the file
    buf = bytearray(_rand(512 * 64, seed=1))
    buf[volume_off:volume_off] = b""  # (no-op, keep size)
    buf[volume_off + 3: volume_off + 11] = b"NTFS    "
    p = tmp_path / "disk.img"
    p.write_bytes(bytes(buf))

    # search the whole file
    found = formats.detect(str(p), intact_start=0)
    ntfs = [f for f in found if "NTFS" in f["name"]]
    assert ntfs, "should find the NTFS boot sector"
    assert ntfs[0]["where"] == "interior"
    assert ntfs[0]["offset"] == volume_off


def test_detect_respects_intact_start(tmp_path):
    # An NTFS sector before intact_start must be ignored (it's inside the encrypted region).
    buf = bytearray(_rand(512 * 40, seed=2))
    buf[3:11] = b"NTFS    "                 # at offset 0 -- inside the "encrypted" front
    p = tmp_path / "d.img"
    p.write_bytes(bytes(buf))
    found = formats.detect(str(p), intact_start=512 * 10)
    assert not any("NTFS" in f["name"] for f in found)


def test_no_false_positive_on_random(tmp_path):
    p = tmp_path / "r.bin"
    p.write_bytes(_rand(2 * 1024 * 1024, seed=3))
    found = formats.detect(str(p))
    assert found == []


def test_scan_report_carries_formats(tmp_path):
    # front-only encrypted file whose intact body contains a ZIP header at the boundary
    enc = _rand(1024 * 1024, seed=4)
    body = b"PK\x03\x04" + (b"content bytes " * 100000)
    p = tmp_path / "s.bin"
    p.write_bytes(enc + body)
    report = engine.scan(str(p))
    assert report.pattern == "front-only"
    assert any("ZIP" in f["name"] for f in report.formats)
    # the ZIP header should be reported at the boundary, not offset 0
    zf = next(f for f in report.formats if "ZIP" in f["name"])
    assert zf["offset"] == report.boundary_offset


def test_fully_encrypted_skips_format_detection(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(_rand(2 * 1024 * 1024, seed=5))
    report = engine.scan(str(p))
    assert report.pattern == "fully-encrypted"
    assert report.formats == []
