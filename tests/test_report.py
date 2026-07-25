"""HTML triage report generation."""
import hashlib
import random

import pytest

from rprt import engine, report


@pytest.fixture
def scanned_front_only(tmp_path):
    rng = random.Random(1)
    enc = bytes(rng.getrandbits(8) for _ in range(2 * 1024 * 1024))
    text = (b"the quick brown fox " * 100000)[:6 * 1024 * 1024]
    p = tmp_path / "sample.bin"
    p.write_bytes(enc + text)
    rep = engine.scan(str(p))
    return str(p), rep


def test_sha256_of_input_matches_hashlib(tmp_path):
    data = b"some bytes to hash" * 1000
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    assert report.sha256_of_input(str(p)) == hashlib.sha256(data).hexdigest()


def test_report_is_self_contained_html(scanned_front_only):
    path, rep = scanned_front_only
    doc = report.build_html_report(path, rep, sha256="a" * 64)
    assert doc.lstrip().startswith("<!doctype html>")
    # self-contained: no EMBEDDED external resources (fonts/images/scripts/stylesheets) that
    # would fail to load offline. Hyperlinks (<a href>) are fine; they load nothing.
    for bad in ("src=", "<link", "<script", "@import", "url(http", "cdn."):
        assert bad not in doc.lower(), f"report embeds external resource: {bad}"
    # inline SVG entropy strip present
    assert "<svg" in doc


def test_report_contains_headline_and_hash(scanned_front_only):
    path, rep = scanned_front_only
    doc = report.build_html_report(path, rep, sha256="deadbeef" * 8)
    assert f"{rep.recoverable_pct:.2f}% recoverable" in doc
    assert "deadbeef" * 8 in doc
    assert "not decryption" in doc.lower()  # caveat present


def test_report_escapes_html_in_path(tmp_path):
    rng = random.Random(2)
    p = tmp_path / "weird.bin"
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(4096)))
    rep = engine.scan(str(p))
    doc = report.build_html_report(str(p), rep, display_name="<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc


def test_write_html_report_creates_file(scanned_front_only, tmp_path):
    path, rep = scanned_front_only
    out = str(tmp_path / "out.html")
    assert report.write_html_report(path, rep, out) == out
    with open(out, encoding="utf-8") as f:
        assert "ScanCrypt" in f.read()


def test_entropy_segments_cover_the_file(scanned_front_only):
    path, rep = scanned_front_only
    segs = report.entropy_segments(rep)
    assert segs
    # every segment is a valid kind and within 0..1
    for x, w, kind in segs:
        assert kind in ("encrypted", "intact", "zero")
        assert 0.0 <= x <= 1.0 and w >= 0.0
    # front-only: the first segment starts at 0 and is encrypted
    assert segs[0][0] == 0.0
    assert any(k == "encrypted" for _, _, k in segs)
    assert any(k == "intact" for _, _, k in segs)


def test_family_shown_when_identified(tmp_path):
    magic = bytes.fromhex("89ce296df32e5921")
    rng = random.Random(3)
    p = tmp_path / "x.ndm448"
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(4096)) + magic)
    rep = engine.scan(str(p))
    doc = report.build_html_report(str(p), rep)
    assert "Makop" in doc


def test_expected_boundary_fraction_from_family(tmp_path):
    magic = bytes.fromhex("89ce296df32e5921")
    rng = random.Random(3)
    p = tmp_path / "x.ndm448"
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(4096)) + magic)
    rep = engine.scan(str(p))
    assert report.expected_boundary_fraction(rep) == 0.34


def test_expected_boundary_fraction_none_without_family(scanned_front_only):
    _, rep = scanned_front_only
    assert rep.family is None
    assert report.expected_boundary_fraction(rep) is None


def test_marker_line_rendered_in_svg_when_family_identified(tmp_path):
    # A front-only .ndm448 whose boundary is within the ~1/3 extent: the SVG should draw
    # the dashed intended-extent marker line and mention it in the caption.
    magic = bytes.fromhex("89ce296df32e5921")
    rng = random.Random(9)
    enc = bytes(rng.getrandbits(8) for _ in range(1024 * 1024))
    text = (b"plain text content " * 200000)[:7 * 1024 * 1024]
    p = tmp_path / "big.ndm448"
    p.write_bytes(enc + text + magic)
    rep = engine.scan(str(p))
    doc = report.build_html_report(str(p), rep)
    assert "stroke-dasharray" in doc
    assert "intended" in doc.lower()


def test_no_marker_line_without_family(scanned_front_only):
    path, rep = scanned_front_only
    doc = report.build_html_report(path, rep)
    assert "stroke-dasharray" not in doc


def test_default_footer_carries_ironsights_attribution(scanned_front_only):
    path, rep = scanned_front_only
    doc = report.build_html_report(path, rep)
    # discreet, always-on credit; not the configurable pitch
    assert "IronSights" in doc
    assert "scancrypt.org" in doc
    assert "recovery assistance" not in doc  # no assist block by default


def test_contact_block_only_when_supplied(scanned_front_only):
    path, rep = scanned_front_only
    contact = {"firm": "Acme IR", "url": "https://acme.example/contact"}
    doc = report.build_html_report(path, rep, contact=contact)
    assert "recovery assistance" in doc
    assert "Acme IR" in doc
    assert "https://acme.example/contact" in doc


def test_contact_block_escapes_firm(scanned_front_only):
    path, rep = scanned_front_only
    contact = {"firm": "<b>x</b>", "url": "javascript:alert(1)"}
    doc = report.build_html_report(path, rep, contact=contact)
    assert "<b>x</b>" not in doc
    assert "&lt;b&gt;" in doc


def test_contact_from_env(monkeypatch):
    monkeypatch.delenv("RPRT_FIRM_NAME", raising=False)
    assert report.contact_from_env() is None
    monkeypatch.setenv("RPRT_FIRM_NAME", "Acme IR")
    monkeypatch.setenv("RPRT_FIRM_URL", "https://acme.example")
    c = report.contact_from_env()
    assert c["firm"] == "Acme IR" and c["url"] == "https://acme.example"
