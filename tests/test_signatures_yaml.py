"""Validate the shipped signatures.yaml and the honesty rules that guard it.

Contributions land in signatures.yaml; this is the CI gate that keeps a bad or dishonest
entry from merging.
"""
import pytest

from rprt import signatures


def test_yaml_loads_and_matches_expected_families():
    names = {f.name for f in signatures.FAMILIES}
    assert "Makop/Phobos (.ndm448 variant)" in names
    assert len(signatures.FAMILIES) >= 8


def test_every_family_obeys_the_honesty_rules():
    for f in signatures.FAMILIES:
        assert f.provenance in ("validated", "public-reporting"), f.name
        assert f.large_file_pattern in signatures._VALID_PATTERNS, f.name
        # a measured footer or a specific fraction is only credible on a validated row
        if f.provenance != "validated":
            assert f.footer_magic is None, f"{f.name}: footer on a public-reporting row"
            assert f.typical_max_encrypted_fraction is None, f"{f.name}: fraction on public row"
        if f.typical_max_encrypted_fraction is not None:
            assert 0.0 < f.typical_max_encrypted_fraction < 1.0, f.name


def test_only_makop_is_validated():
    validated = [f for f in signatures.FAMILIES if f.provenance == "validated"]
    assert [f.name for f in validated] == ["Makop/Phobos (.ndm448 variant)"]


def test_all_regexes_compile():
    import re
    for f in signatures.FAMILIES:
        for pat in (f.extension_regex, f.note_name_regex):
            if pat:
                re.compile(pat)   # raises if invalid


def test_loader_rejects_footer_on_public_reporting():
    with pytest.raises(ValueError):
        signatures._family_from_dict({
            "name": "Fabricated", "provenance": "public-reporting",
            "footer_magic": "deadbeef",   # not allowed unless validated
        })


def test_loader_rejects_fraction_on_public_reporting():
    with pytest.raises(ValueError):
        signatures._family_from_dict({
            "name": "Fabricated", "provenance": "public-reporting",
            "typical_max_encrypted_fraction": 0.5,
        })


def test_loader_rejects_bad_provenance_and_pattern():
    with pytest.raises(ValueError):
        signatures._family_from_dict({"name": "X", "provenance": "made-up"})
    with pytest.raises(ValueError):
        signatures._family_from_dict({"name": "X", "large_file_pattern": "sideways"})


def test_loader_rejects_out_of_range_fraction():
    with pytest.raises(ValueError):
        signatures._family_from_dict({
            "name": "X", "provenance": "validated", "typical_max_encrypted_fraction": 1.5})


def test_loader_rejects_bad_regex():
    with pytest.raises(ValueError):
        signatures._family_from_dict({"name": "X", "extension_regex": "([unclosed"})


def test_valid_entry_round_trips():
    fam = signatures._family_from_dict({
        "name": "Example",
        "provenance": "validated",
        "extension_regex": r"\.example$",
        "footer_magic": "0011aabb",
        "large_file_pattern": "front-only",
        "typical_max_encrypted_fraction": 0.25,
        "note_markers": ["all your files"],
    })
    assert fam.footer_magic == bytes.fromhex("0011aabb")
    assert fam.typical_max_encrypted_fraction == 0.25
    assert fam.note_markers == ("all your files",)
