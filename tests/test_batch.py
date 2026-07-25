"""Incident-level batch triage across a directory tree."""
import os
import random

import pytest

from rprt import batch, report


MAKOP_MAGIC = bytes.fromhex("89ce296df32e5921")


def _rand(n, seed):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def _text(n):
    return (b"plain readable text content " * (n // 20 + 1))[:n]


@pytest.fixture
def incident_tree(tmp_path):
    """A share with a mix: a front-only-encrypted large file, a fully-encrypted small
    .ndm448, an untouched text file, and a nested directory."""
    # front-only: 2 MB encrypted head + 6 MB text
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "database.mdf").write_bytes(_rand(2 * 1024 * 1024, 1) + _text(6 * 1024 * 1024))
    # fully-encrypted small ransomware file
    (tmp_path / "notes.txt.ndm448").write_bytes(_rand(4096, 2) + MAKOP_MAGIC)
    # untouched file
    (tmp_path / "readme.txt").write_bytes(_text(500_000))
    # nested untouched
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "report.txt").write_bytes(_text(300_000))
    # a zero-byte file that must be skipped
    (tmp_path / "empty.dat").write_bytes(b"")
    return str(tmp_path)


def test_scan_tree_aggregates(incident_tree):
    result = batch.scan_tree(incident_tree)
    assert result.scanned == 4          # empty.dat skipped by min_size
    assert result.errors == 0
    assert result.total_bytes > 0
    # most bytes (the big front-only file's tail + the text files) are recoverable
    assert 60 < result.recoverable_pct <= 100


def test_scan_tree_per_file_classification(incident_tree):
    result = batch.scan_tree(incident_tree)
    by_name = {os.path.basename(f.path): f for f in result.files}
    assert by_name["database.mdf"].pattern == "front-only"
    assert by_name["notes.txt.ndm448"].pattern == "fully-encrypted"
    assert by_name["notes.txt.ndm448"].recoverable_bytes == 0
    assert by_name["readme.txt"].pattern == "fully-intact"
    # family fingerprint surfaced for the ransomware file
    assert "Makop" in (by_name["notes.txt.ndm448"].family or "")


def test_family_and_pattern_breakdowns(incident_tree):
    result = batch.scan_tree(incident_tree)
    assert any("Makop" in k for k in result.family_breakdown())
    pb = result.pattern_breakdown()
    assert pb.get("front-only") == 1
    assert pb.get("fully-encrypted") == 1
    assert pb.get("fully-intact") == 2


def test_min_size_filter(incident_tree):
    # raise the floor above the small files -> only the 8 MB mdf remains
    result = batch.scan_tree(incident_tree, min_size=1_000_000)
    assert result.scanned == 1
    assert os.path.basename(result.files[0].path) == "database.mdf"


def test_hashing_records_sha256(incident_tree):
    import hashlib
    result = batch.scan_tree(incident_tree, do_hash=True)
    fr = next(f for f in result.files if os.path.basename(f.path) == "readme.txt")
    with open(fr.path, "rb") as fh:
        assert fr.sha256 == hashlib.sha256(fh.read()).hexdigest()


def test_write_csv(incident_tree, tmp_path):
    result = batch.scan_tree(incident_tree)
    out = str(tmp_path / "out.csv")
    batch.write_csv(result, out)
    with open(out, encoding="utf-8") as f:
        text = f.read()
    assert "path,size_bytes,pattern" in text
    assert "database.mdf" in text and "front-only" in text


def test_incident_report_self_contained(incident_tree):
    result = batch.scan_tree(incident_tree)
    doc = report.build_incident_report(result)
    assert doc.lstrip().startswith("<!doctype html>")
    # no embedded external resources; hyperlinks are allowed
    for bad in ("src=", "<link", "<script", "@import", "url(http", "cdn."):
        assert bad not in doc.lower()
    assert "% recoverable" in doc
    assert "Makop" in doc


def test_error_in_one_file_does_not_stop_scan(incident_tree, monkeypatch):
    from rprt import engine
    real_scan = engine.scan
    calls = {"n": 0}

    def flaky(path, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real_scan(path, **kw)

    monkeypatch.setattr(batch.engine, "scan", flaky)
    result = batch.scan_tree(incident_tree)
    assert result.errors == 1
    assert result.scanned == 3          # the rest still scanned
    assert any(f.error for f in result.files)
