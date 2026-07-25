"""Ransomware family fingerprinting.

Footer magic and extension pattern for the Makop/.ndm448 family were confirmed
against real encrypted samples: fully-encrypted files ending in the
8-byte magic 89 CE 29 6D F3 2E 59 21, renamed with a .ndm448 extension.
"""
from rprt import signatures

MAKOP_MAGIC = bytes.fromhex("89ce296df32e5921")


def test_identify_by_footer_magic():
    trailer = b"\x00" * 40 + MAKOP_MAGIC
    ident = signatures.identify(trailer=trailer)
    assert ident.identified
    assert "footer_magic" in ident.matched_on
    assert ident.family.large_file_pattern == "front-only"


def test_identify_by_extension():
    ident = signatures.identify(filename="document.pdf.[VICTIMID].[attacker@example.org].ndm448")
    assert ident.identified
    assert "extension" in ident.matched_on


def test_identify_by_both_raises_matched_count():
    ident = signatures.identify(filename="x.ndm448", trailer=b"zz" + MAKOP_MAGIC)
    assert set(ident.matched_on) == {"footer_magic", "extension"}


def test_no_false_positive_on_benign_input():
    ident = signatures.identify(filename="report.pdf", trailer=b"%%EOF\n")
    assert not ident.identified
    assert ident.to_dict()["family"] is None


def test_identify_path_reads_trailer(tmp_path):
    p = tmp_path / "sample.ndm448"
    p.write_bytes(b"\xff" * 500 + MAKOP_MAGIC)
    ident = signatures.identify_path(str(p))
    assert ident.identified
    # both the extension and the footer should match on a real file
    assert set(ident.matched_on) == {"footer_magic", "extension"}


def test_scan_report_carries_family(tmp_path):
    from rprt import engine
    p = tmp_path / "small.ndm448"
    # fully high-entropy small file ending in the magic, like a real .ndm448
    import random
    rng = random.Random(1)
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(4096)) + MAKOP_MAGIC)
    report = engine.scan(str(p))
    assert report.family is not None
    assert "Makop" in report.family["family"]


def test_family_carries_max_encrypted_fraction():
    ident = signatures.identify(trailer=b"z" + MAKOP_MAGIC)
    d = ident.to_dict()
    assert d["typical_max_encrypted_fraction"] == 0.34


def test_makop_provenance_is_validated():
    ident = signatures.identify(trailer=b"z" + MAKOP_MAGIC)
    assert ident.to_dict()["provenance"] == "validated"


def test_public_reporting_families_identify_by_extension():
    # a representative set of the added intermittent-encryption families
    for ext, expect in [
        ("victim.xlsx.lockbit", "LockBit"),
        ("db.mdf.basta", "BlackBasta"),
        ("server.vhdx.play", "Play"),
        ("backup.vib.royal", "Royal"),
        ("share.zip.akira", "Akira"),
    ]:
        ident = signatures.identify(filename=ext)
        assert ident.identified, ext
        assert expect in ident.family.name
        assert ident.matched_on == ["extension"]


def test_public_reporting_families_marked_and_have_no_unverified_fraction():
    # public-reporting rows must not carry a fabricated footer or encrypted-fraction
    for fam in signatures.FAMILIES:
        if fam.provenance == "public-reporting":
            assert fam.footer_magic is None, fam.name
            assert fam.typical_max_encrypted_fraction is None, fam.name


def test_public_reporting_match_carries_provenance(tmp_path):
    ident = signatures.identify(filename="x.play")
    d = ident.to_dict()
    assert d["provenance"] == "public-reporting"
    assert d["typical_max_encrypted_fraction"] is None


def test_extensions_do_not_match_ordinary_filenames():
    # anchored extensions must not fire on unrelated names
    for benign in ("notes.txt", "playlist.m3u", "display.cfg", "royalty_report.pdf"):
        assert not signatures.identify(filename=benign).identified, benign


def test_boundary_beyond_family_fraction_gets_advisory(tmp_path):
    from rprt import engine
    import random
    rng = random.Random(5)
    # front-encrypted region ~50% of the file (beyond the family's ~1/3), named .ndm448,
    # so the family-expectation cross-check should append an advisory to the note.
    half = 3 * 1024 * 1024
    enc = bytes(rng.getrandbits(8) for _ in range(half))
    text = (b"plain text content " * 100000)[:half]
    p = tmp_path / "big.ndm448"
    p.write_bytes(enc + text)
    report = engine.scan(str(p))
    assert report.pattern == "front-only"
    assert "Advisory" in report.note
    assert "typically encrypts" in report.note


def test_boundary_within_family_fraction_no_advisory(tmp_path):
    from rprt import engine
    import random
    rng = random.Random(6)
    # small encrypted front (~12%), within the ~1/3 expectation -> no advisory
    enc = bytes(rng.getrandbits(8) for _ in range(1024 * 1024))
    text = (b"plain text content " * 200000)[:7 * 1024 * 1024]
    p = tmp_path / "ok.ndm448"
    p.write_bytes(enc + text)
    report = engine.scan(str(p))
    assert report.pattern == "front-only"
    assert "Advisory" not in report.note
