"""rprt.fingerprint — turn an encrypted file into a privacy-safe, submittable family stub.

Community signatures are the thing that keeps ScanCrypt naming new strains, but writing a
pull request against a YAML schema is a high bar for a victim in the middle of an incident.
This module lowers it to one command: point ScanCrypt at an encrypted file and it emits the
structural markers a maintainer needs to add a family -- the encrypted extension, the trailing
"magic candidate" bytes, the observed large-file encryption pattern, and a nearby ransom
note's filename/phrases -- as a ready-to-paste signatures.yaml block and a pre-filled GitHub
issue link.

PRIVACY: this reads ONLY structural family markers. It never reads or emits file *contents*:
just the filename, the last few trailing bytes (a family key-trailer marker, not plaintext),
and -- if a ransom note sits next to the file -- that note's filename and the generic phrases
that mark it as a note. A victim can submit this without leaking any data.

Honesty: a submission is always `provenance: public-reporting` (the submitter has not verified
it in-house), so per the signatures.yaml rules the stub carries NO footer_magic or
typical_max_encrypted_fraction field -- the observed trailing bytes and boundary go in `notes:`
as evidence for a maintainer to validate before promoting the row to `validated`.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

from . import signatures, ransomnote

# How many trailing bytes to show as a magic candidate. Small: enough to spot a fixed family
# marker, far too little to be file content or a usable key.
TRAILER_BYTES = 16
_ISSUE_TEMPLATE = "ransomware-sample.yml"


@dataclass
class Fingerprint:
    filename: str
    ext_suffix: Optional[str] = None            # final extension token, e.g. "ndm448"
    ext_regex: Optional[str] = None             # suggested extension_regex, e.g. r"\.ndm448$"
    size: int = 0
    trailer_hex: Optional[str] = None           # last TRAILER_BYTES bytes, hex
    pattern: Optional[str] = None               # large-file pattern from the scan
    boundary_offset: Optional[int] = None
    encrypted_pct: Optional[float] = None
    recoverable_pct: Optional[float] = None
    note_filename: Optional[str] = None
    note_name_regex: Optional[str] = None
    note_markers: list = field(default_factory=list)
    known_family: Optional[str] = None          # already-matched family, if any
    known_provenance: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "filename": self.filename, "ext_suffix": self.ext_suffix,
            "ext_regex": self.ext_regex, "size": self.size, "trailer_hex": self.trailer_hex,
            "pattern": self.pattern, "boundary_offset": self.boundary_offset,
            "encrypted_pct": self.encrypted_pct, "recoverable_pct": self.recoverable_pct,
            "note_filename": self.note_filename, "note_name_regex": self.note_name_regex,
            "note_markers": self.note_markers, "known_family": self.known_family,
            "known_provenance": self.known_provenance,
        }


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _extension_suffix(filename: str) -> Optional[str]:
    """The final extension token of a ransomware-renamed file. Handles the common
    'name.ext.[ID].[email].family' shape by taking the token after the last dot."""
    base = os.path.basename(filename)
    if "." not in base:
        return None
    tok = base.rsplit(".", 1)[-1]
    # a plausible ransomware extension: short-ish, alphanumeric-ish, not a whole sentence
    if tok and len(tok) <= 24 and re.fullmatch(r"[A-Za-z0-9_%+-]{1,24}", tok):
        return tok
    return None


def _find_nearby_note(path: str):
    """Look in the file's own directory for a ransom note; return its NoteIdentification or
    None. Only the note's filename and generic markers are used -- never victim-specific text."""
    d = os.path.dirname(os.path.abspath(path))
    try:
        entries = sorted(os.listdir(d))
    except OSError:
        return None
    for name in entries:
        if not ransomnote.looks_like_note_name(name):
            continue
        ident = ransomnote.identify_path(os.path.join(d, name))
        if ident.is_ransom_note:
            return name, ident
    return None


def build(path: str, scan_report=None) -> Fingerprint:
    """Build a Fingerprint for `path`. If a scan report is supplied, its pattern/boundary are
    reused; otherwise a fast boundary scan is run (no full-file read)."""
    filename = os.path.basename(path)
    fp = Fingerprint(filename=filename)
    try:
        fp.size = os.path.getsize(path)
    except OSError:
        fp.size = 0

    ext = _extension_suffix(filename)
    if ext:
        fp.ext_suffix = ext
        fp.ext_regex = r"\." + re.escape(ext) + r"$"

    # trailing "magic candidate" bytes -- tiny, structural, not content
    try:
        with open(path, "rb") as f:
            f.seek(max(0, fp.size - TRAILER_BYTES))
            fp.trailer_hex = f.read(TRAILER_BYTES).hex() or None
    except OSError:
        fp.trailer_hex = None

    # already a known family?
    ident = signatures.identify_path(path)
    if ident.identified:
        fp.known_family = ident.family.name
        fp.known_provenance = ident.family.provenance

    # large-file pattern + boundary from a scan (fast boundary-only path)
    if scan_report is None:
        try:
            from . import engine
            scan_report = engine.scan(path, boundary_only=True)
        except Exception:  # noqa: BLE001 -- fingerprint is best-effort; carry on without a scan
            scan_report = None
    if scan_report is not None:
        fp.pattern = getattr(scan_report, "pattern", None)
        fp.boundary_offset = getattr(scan_report, "boundary_offset", None)
        fp.encrypted_pct = getattr(scan_report, "encrypted_pct", None)
        fp.recoverable_pct = getattr(scan_report, "recoverable_pct", None)

    note = _find_nearby_note(path)
    if note:
        note_name, ident_n = note
        fp.note_filename = note_name
        fp.note_name_regex = r"^" + re.escape(note_name) + r"$"
        fp.note_markers = list(ident_n.generic_markers)
        if ident_n.family and not fp.known_family:
            fp.known_family = ident_n.family
            fp.known_provenance = ident_n.provenance

    return fp


def _yaml_pattern(pattern: Optional[str]) -> str:
    """Map a scan pattern to a signatures.yaml large_file_pattern value (honest fallback)."""
    p = (pattern or "").lower()
    if p == "front-only":
        return "front-only"
    if p in ("periodic-intermittent", "mixed", "non-contiguous"):
        return "periodic-intermittent"
    if p == "fully-encrypted":
        return "full"
    return "unknown"


def to_yaml_stub(fp: Fingerprint) -> str:
    """A ready-to-paste signatures.yaml entry. Always public-reporting, so no footer_magic /
    fraction fields (the observed trailing bytes + boundary go in notes as evidence)."""
    lines = ["  - name: \"REPLACE WITH THE FAMILY NAME (e.g. from the ransom note)\"",
             "    provenance: public-reporting"]
    if fp.ext_regex:
        lines.append(f"    extension_regex: '{fp.ext_regex}'")
    lines.append(f"    large_file_pattern: {_yaml_pattern(fp.pattern)}")
    if fp.note_name_regex:
        lines.append(f"    note_name_regex: '{fp.note_name_regex}'")
    ev = []
    if fp.trailer_hex:
        ev.append(f"observed trailing bytes (hex, last {TRAILER_BYTES}): {fp.trailer_hex}")
    if fp.boundary_offset is not None and fp.size:
        ev.append(f"observed front boundary at {fp.encrypted_pct:.4f}% of a "
                  f"{_human_size(fp.size)} file")
    ev.append("submitted via `scancrypt --fingerprint`. A maintainer should confirm the footer "
              "magic across several files before promoting this row to validated.")
    note_body = " ".join(ev)
    lines.append("    notes: >-")
    for chunk in _wrap(note_body, 78):
        lines.append("      " + chunk)
    return "\n".join(lines)


def _wrap(text: str, width: int):
    out, line = [], ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line); line = word
        else:
            line = word if not line else line + " " + word
    if line:
        out.append(line)
    return out


def issue_url(fp: Fingerprint, repo: str = "ironsightscyber/scancrypt") -> str:
    """A GitHub 'new issue' URL that pre-fills the ransomware-sample issue form."""
    fields = {
        "template": _ISSUE_TEMPLATE,
        "title": f"New family: {fp.ext_suffix or 'unknown extension'}",
        "extension": ("." + fp.ext_suffix) if fp.ext_suffix else "",
        "note_filename": fp.note_filename or "",
        "footer_hex": fp.trailer_hex or "",
        "pattern": _yaml_pattern(fp.pattern),
        "boundary": (f"{fp.encrypted_pct:.4f}% of {_human_size(fp.size)}"
                     if fp.encrypted_pct is not None else ""),
    }
    q = "&".join(f"{k}={quote(str(v))}" for k, v in fields.items() if v)
    return f"https://github.com/{repo}/issues/new?{q}"


def render_text(fp: Fingerprint, repo: str = "ironsightscyber/scancrypt") -> str:
    """Human-readable fingerprint report for the CLI."""
    L = []
    L.append("ScanCrypt fingerprint — help ScanCrypt recognise this ransomware")
    L.append("")
    L.append("  Metadata only. No file contents are read or shared — safe to submit.")
    L.append("")
    L.append(f"  Encrypted extension : .{fp.ext_suffix}" if fp.ext_suffix
             else "  Encrypted extension : (none detected)")
    if fp.pattern:
        rec = f", ~{fp.recoverable_pct:.1f}% recoverable" if fp.recoverable_pct is not None else ""
        L.append(f"  Large-file pattern  : {fp.pattern} ({fp.encrypted_pct:.4f}% encrypted{rec})")
    if fp.trailer_hex:
        L.append(f"  Trailing bytes (hex): {fp.trailer_hex}   (magic candidate, last {TRAILER_BYTES})")
    if fp.note_filename:
        fam = f" — matches {fp.known_family}" if fp.known_family else ""
        L.append(f"  Ransom note nearby  : {fp.note_filename}{fam}")
    if fp.known_family:
        L.append(f"  Known family        : {fp.known_family} — already in ScanCrypt "
                 f"({fp.known_provenance}) ✓")
        L.append("")
        L.append("  This strain is already recognised. If this looks like a NEW variant "
                 "(different\n  extension or note), the stub below still helps — otherwise "
                 "nothing to submit.")
    L.append("")
    L.append("  ── paste into signatures.yaml, or use the issue form ──")
    L.append("")
    L.append(to_yaml_stub(fp))
    L.append("")
    L.append("  ── or open a pre-filled submission form (no login needed to view) ──")
    L.append("")
    L.append("  " + issue_url(fp, repo))
    return "\n".join(L)
