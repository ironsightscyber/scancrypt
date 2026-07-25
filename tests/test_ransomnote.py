"""Ransom-note detection and family identification.

The Makop note text below is the family template (the distinctive phrasing reused across
Makop campaigns), with victim-specific contact details removed -- matching the markers in
the validated signature.
"""
import os

from rprt import ransomnote, batch

MAKOP_NOTE = """Dear Management,
If you are reading this message, it means that:
 - your network infrastructure has been compromised,
 - critical data was leaked,
 - files are encrypted
 1. THE FOLLOWING IS STRICTLY FORBIDDEN
1.1 EDITING FILES ON HDD.
 Renaming, copying or moving any files could DAMAGE the cipher and
 decryption will be impossible.
"""

GENERIC_NOTE = """All your files have been encrypted!
To recover your data you must pay in bitcoin. Contact us at the .onion address.
Do not try to decrypt yourself.
"""


def test_makop_note_identified_by_name_and_content(tmp_path):
    p = tmp_path / "+README-WARNING+.txt"
    p.write_text(MAKOP_NOTE)
    ident = ransomnote.identify_path(str(p))
    assert ident.is_ransom_note
    assert "Makop" in ident.family
    assert set(ident.matched_on) == {"note_name", "note_content"}
    assert ident.provenance == "validated"


def test_makop_content_matches_even_with_generic_name(tmp_path):
    # content markers alone should still identify Makop even if the file was renamed
    p = tmp_path / "readme.txt"
    p.write_text(MAKOP_NOTE)
    ident = ransomnote.identify_path(str(p))
    assert ident.family and "Makop" in ident.family
    assert "note_content" in ident.matched_on


def test_generic_ransom_note_detected_without_family(tmp_path):
    p = tmp_path / "HOW_TO_DECRYPT.txt"
    p.write_text(GENERIC_NOTE)
    ident = ransomnote.identify_path(str(p))
    assert ident.is_ransom_note
    assert ident.family is None            # not attributable to a specific family
    assert len(ident.generic_markers) >= 2


def test_benign_file_not_a_note(tmp_path):
    p = tmp_path / "readme.txt"
    p.write_text("Build instructions: run make, then make install. See docs for details.")
    ident = ransomnote.identify_path(str(p))
    assert not ident.is_ransom_note
    assert ident.family is None


def test_distinctive_note_name_alone_identifies(tmp_path):
    # Royal's README.royal.txt is distinctive enough to attribute on name alone
    p = tmp_path / "README.royal.txt"
    p.write_text(GENERIC_NOTE)
    ident = ransomnote.identify_path(str(p))
    assert ident.family == "Royal"
    assert ident.matched_on == ["note_name"]


def test_find_notes_walks_tree(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "+README-WARNING+.txt").write_text(MAKOP_NOTE)
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "+README-WARNING+.txt").write_text(MAKOP_NOTE)
    (tmp_path / "notes.txt").write_text("just my personal notes, nothing to see")
    notes = ransomnote.find_notes(str(tmp_path))
    assert notes
    assert all("Makop" in n.family for n in notes if n.family)
    assert "Makop/Phobos (.ndm448 variant)" in ransomnote.families_seen(notes)


def test_batch_surfaces_note_identified_strain(tmp_path):
    import random
    rng = random.Random(1)
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "data.mdf").write_bytes(
        bytes(rng.getrandbits(8) for _ in range(1024 * 1024)) + b"text " * 400000)
    (tmp_path / "+README-WARNING+.txt").write_text(MAKOP_NOTE)
    result = batch.scan_tree(str(tmp_path))
    assert result.notes
    assert result.identified_strain() and "Makop" in result.identified_strain()
    assert "Makop/Phobos (.ndm448 variant)" in result.note_families()
    # the incident report names the strain and how it was identified
    from rprt import report
    doc = report.build_incident_report(result)
    assert "Ransomware strain" in doc and "Makop" in doc and "ransom note" in doc
