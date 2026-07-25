"""rprt.signatures — known-ransomware fingerprinting.

Many families append a fixed trailer to every encrypted file and/or rename it with
a recognisable extension. Spotting those tells the tool *which* family it's looking
at before it scans a byte, which in turn implies the expected encryption pattern and
lets a triage report name the strain.

This is a lightweight, generic IOC table (family-level magic footers and extension
patterns only -- no victim-specific identifiers). It needs upkeep as families evolve;
that's expected, per the project's honest-caveats note.

Each family carries a `provenance`: "validated" (confirmed against a real sample here) or
"public-reporting" (extension/behaviour from published threat intel, not yet verified
in-house). Identification never changes the recovery numbers -- it only names the strain
and sets expectations -- and the recovery engine itself is family-agnostic, so an
unmatched or wrongly-guessed family does not affect whether intact bytes are recovered.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Family:
    name: str
    # Fixed byte sequence at the very end of every encrypted file, if the family uses one.
    footer_magic: Optional[bytes] = None
    # Regex matched against the (case-insensitive) filename.
    extension_regex: Optional[str] = None
    # Typical large-file behaviour, to pre-select scan strategy / set expectations.
    large_file_pattern: str = "unknown"   # "front-only" | "periodic-intermittent" | "configurable" | "full" | "unknown"
    # Encrypted files carry an appended key/metadata trailer, so ciphertext < file size.
    appends_trailer: bool = True
    # Upper bound on the fraction of a large file this family intends to encrypt, if known.
    # Used only as an advisory sanity check on a detected front-only boundary -- a boundary
    # beyond this is flagged for a second look, it does not change the recovery estimate.
    # Left None unless a specific default is known, to avoid a fabricated marker/advisory.
    typical_max_encrypted_fraction: Optional[float] = None
    # How much to trust a match. "validated": confirmed against a real sample in-house.
    # "public-reporting": extension/behaviour taken from published threat intel, not yet
    # verified against a sample here -- surfaced to the user so the match reads as "likely".
    provenance: str = "public-reporting"
    # Ransom-note fingerprints: the note filename pattern this family drops, and distinctive
    # (family-generic, non-victim-specific) content phrases from its note template. A note
    # match is an independent identification signal that corroborates the extension/footer.
    note_name_regex: Optional[str] = None
    note_markers: tuple = ()
    notes: str = ""


# --- Identification table -------------------------------------------------------------
#
# The families themselves live in signatures.yaml (plain data), so contributors can add one
# without touching code and a future rewrite in another language can load the same file.
# This module just parses that data into Family objects and does the matching.
#
# Only Makop is VALIDATED (footer + extension confirmed against real .ndm448 samples; large-
# file behaviour from static analysis of the encryptor binary). The rest are PUBLIC-REPORTING:
# a stable extension and the documented fact that the family partially encrypts large files.
# Families that randomise the extension per victim (BlackCat/ALPHV, LockBit 3.0, Qilin) are
# left out on purpose: no honest signature would match them. Recovery still works on them;
# identification only names the strain.
_VALID_PATTERNS = {"front-only", "periodic-intermittent", "configurable", "full", "unknown"}
_VALID_PROVENANCE = {"validated", "public-reporting"}


def _family_from_dict(d: dict) -> Family:
    """Build a Family from one signatures.yaml entry, enforcing the honesty rules so a bad
    contribution fails loudly rather than producing false identifications."""
    name = d.get("name")
    if not name:
        raise ValueError("signature entry is missing 'name'")
    provenance = d.get("provenance", "public-reporting")
    if provenance not in _VALID_PROVENANCE:
        raise ValueError(f"{name}: provenance must be one of {sorted(_VALID_PROVENANCE)}")
    pattern = d.get("large_file_pattern", "unknown")
    if pattern not in _VALID_PATTERNS:
        raise ValueError(f"{name}: large_file_pattern must be one of {sorted(_VALID_PATTERNS)}")

    footer_hex = d.get("footer_magic")
    frac = d.get("typical_max_encrypted_fraction")
    # A measured footer or a specific encrypted-fraction is only credible on a validated row.
    if provenance != "validated":
        if footer_hex is not None:
            raise ValueError(f"{name}: footer_magic is only allowed on a 'validated' family")
        if frac is not None:
            raise ValueError(f"{name}: typical_max_encrypted_fraction is only allowed on a "
                             f"'validated' family")
    footer = bytes.fromhex(footer_hex) if footer_hex else None
    if frac is not None and not (0.0 < float(frac) < 1.0):
        raise ValueError(f"{name}: typical_max_encrypted_fraction must be between 0 and 1")

    ext = d.get("extension_regex")
    note_name = d.get("note_name_regex")
    for label, pat in (("extension_regex", ext), ("note_name_regex", note_name)):
        if pat is not None:
            try:
                re.compile(pat)
            except re.error as exc:
                raise ValueError(f"{name}: {label} is not a valid regex: {exc}")

    return Family(
        name=name, footer_magic=footer, extension_regex=ext,
        large_file_pattern=pattern, appends_trailer=bool(d.get("appends_trailer", True)),
        typical_max_encrypted_fraction=(float(frac) if frac is not None else None),
        provenance=provenance, note_name_regex=note_name,
        note_markers=tuple(d.get("note_markers") or ()), notes=d.get("notes", "") or "",
    )


def _load_families():
    """Parse signatures.yaml (bundled with the package) into Family objects."""
    import yaml  # declared dependency; a small, standard parser
    try:
        from importlib.resources import files
        raw = (files("rprt") / "signatures.yaml").read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001 -- fall back to a path next to this module (e.g. frozen)
        import os
        with open(os.path.join(os.path.dirname(__file__), "signatures.yaml"), encoding="utf-8") as f:
            raw = f.read()
    data = yaml.safe_load(raw) or {}
    return [_family_from_dict(entry) for entry in data.get("families", [])]


FAMILIES = _load_families()

FOOTER_SCAN_BYTES = 64  # how many trailing bytes to read when fingerprinting


@dataclass
class Identification:
    family: Optional[Family] = None
    matched_on: list = field(default_factory=list)  # "footer_magic" and/or "extension"

    @property
    def identified(self) -> bool:
        return self.family is not None

    def to_dict(self) -> dict:
        return {
            "family": self.family.name if self.family else None,
            "matched_on": self.matched_on,
            "large_file_pattern": self.family.large_file_pattern if self.family else None,
            "appends_trailer": self.family.appends_trailer if self.family else None,
            "typical_max_encrypted_fraction":
                self.family.typical_max_encrypted_fraction if self.family else None,
            "provenance": self.family.provenance if self.family else None,
            "notes": self.family.notes if self.family else "",
        }


def identify(filename: Optional[str] = None, trailer: Optional[bytes] = None) -> Identification:
    """Identify a ransomware family from a filename and/or the trailing bytes of the file.

    Either input is optional; matching on both raises confidence but a footer match alone
    is sufficient (the extension is often stripped or renamed by the time we see the file).
    """
    name_l = filename.lower() if filename else None
    for fam in FAMILIES:
        matched = []
        if fam.footer_magic and trailer and trailer.endswith(fam.footer_magic):
            matched.append("footer_magic")
        if fam.extension_regex and name_l and re.search(fam.extension_regex, name_l):
            matched.append("extension")
        if matched:
            return Identification(family=fam, matched_on=matched)
    return Identification()


def identify_path(path: str) -> Identification:
    """Convenience wrapper: read the trailer from a real file and identify by it + name."""
    import os

    trailer = None
    try:
        with open(path, "rb") as f:
            f.seek(max(0, os.path.getsize(path) - FOOTER_SCAN_BYTES))
            trailer = f.read(FOOTER_SCAN_BYTES)
    except OSError:
        pass
    return identify(filename=os.path.basename(path), trailer=trailer)
