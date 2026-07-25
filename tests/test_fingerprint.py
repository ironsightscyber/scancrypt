import os
import yaml

from rprt import fingerprint, signatures


MAKOP_MAGIC = bytes.fromhex("89ce296df32e5921")


def _write(path, body, magic=b""):
    with open(path, "wb") as f:
        f.write(body + magic)
    return str(path)


def test_extension_suffix_handles_complex_ransomware_names():
    f = fingerprint._extension_suffix
    assert f("payroll.mdf.[AB12CD34].[a@b.org].ndm448") == "ndm448"
    assert f("report.docx.lockbit") == "lockbit"
    assert f("noextension") is None
    # a whole sentence after a dot is not an extension
    assert f("file.this is not an extension") is None


def test_build_identifies_known_family_and_captures_markers(tmp_path):
    p = _write(tmp_path / "x.vhdx.ndm448", os.urandom(4096), MAKOP_MAGIC)
    fp = fingerprint.build(p)
    assert fp.ext_suffix == "ndm448"
    assert fp.ext_regex == r"\.ndm448$"
    assert fp.trailer_hex.endswith("89ce296df32e5921")   # magic candidate present
    assert fp.known_family and "Makop" in fp.known_family
    assert fp.known_provenance == "validated"


def test_yaml_stub_is_valid_against_the_signature_loader(tmp_path):
    # The block we tell people to paste MUST parse and satisfy the honesty rules.
    p = _write(tmp_path / "y.bin.newcrypt", os.urandom(2048))
    fp = fingerprint.build(p)
    stub = fingerprint.to_yaml_stub(fp)
    parsed = yaml.safe_load("families:\n" + stub)
    entry = parsed["families"][0]
    # public-reporting stub must carry no footer_magic / fraction (loader rejects those)
    assert "footer_magic" not in entry
    assert "typical_max_encrypted_fraction" not in entry
    fam = signatures._family_from_dict(entry)          # raises if the stub is invalid
    assert fam.provenance == "public-reporting"
    assert fam.extension_regex == r"\.newcrypt$"


def test_issue_url_prefills_form_fields(tmp_path):
    p = _write(tmp_path / "z.dat.weird", os.urandom(1024))
    fp = fingerprint.build(p)
    url = fingerprint.issue_url(fp)
    assert url.startswith("https://github.com/ironsightscyber/scancrypt/issues/new?")
    assert "template=ransomware-sample.yml" in url
    assert "extension=.weird" in url


def test_nearby_ransom_note_is_picked_up(tmp_path):
    _write(tmp_path / "data.bin.ndm448", os.urandom(1024), MAKOP_MAGIC)
    note = tmp_path / "+README-WARNING+.txt"
    note.write_text("Your files have been encrypted. To decrypt contact us. "
                    "THE FOLLOWING IS STRICTLY FORBIDDEN: EDITING FILES ON HDD.")
    fp = fingerprint.build(str(tmp_path / "data.bin.ndm448"))
    assert fp.note_filename == "+README-WARNING+.txt"
    assert fp.note_name_regex == r"^\+README\-WARNING\+\.txt$"


def test_no_file_contents_leak_into_fingerprint(tmp_path):
    # a secret in the file body must never appear in any fingerprint output
    secret = b"TOP-SECRET-VICTIM-DATA-SHOULD-NOT-LEAK"
    body = os.urandom(8192) + secret + os.urandom(8192)
    p = _write(tmp_path / "s.bin.ndm448", body, MAKOP_MAGIC)
    fp = fingerprint.build(p)
    blob = fingerprint.render_text(fp) + fingerprint.to_yaml_stub(fp) + fingerprint.issue_url(fp)
    assert b"TOP-SECRET".hex() not in (fp.trailer_hex or "")
    assert "TOP-SECRET" not in blob
