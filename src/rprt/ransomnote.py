"""rprt.ransomnote — detect ransom notes and identify the strain from them.

Ransomware drops a note in (almost) every directory. Two things it gives us:
  1. Confirmation that an incident is ransomware (generic note markers), and
  2. An independent family identification -- the note filename and its template phrasing
     -- that corroborates the extension/footer signals from signatures.py. A note match is
     often *stronger* than an extension match, and it can confirm a family for which we
     have no sample (raising a "public-reporting" family to note-corroborated).

Family note fingerprints live on the Family rows in signatures.py (note_name_regex,
note_markers); this module holds the generic "is this a ransom note at all?" detector and
the directory-walk that finds notes in an incident tree. Read-only.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .signatures import FAMILIES

# Generic phrases that, in combination, mark a file as a ransom note regardless of family.
_GENERIC_MARKERS = [
    "your files", "have been encrypted", "files are encrypted", "your network",
    "your data", "decrypt", "decryption", "bitcoin", "btc", ".onion", "ransom",
    "contact us", "recover your", "pay", "private key", "your company", "leaked",
]
# Filenames that commonly hold ransom notes (for finding candidates in a tree).
_NOTE_NAME_HINTS = re.compile(
    r"(readme|read[-_ ]?me|how[-_ ]?to[-_ ]?(decrypt|restore)|decrypt|restore[-_ ]?files?|"
    r"recover[-_ ]?files?|warning|unlock|help[-_ ]?restore|your[-_ ]?files|"
    r"\+README|@Please_Read)", re.IGNORECASE)
_NOTE_MAX_BYTES = 64 * 1024   # notes are small; don't slurp big files while scanning a tree
_MIN_GENERIC_HITS = 2         # require >=2 generic markers to call something a ransom note


@dataclass
class NoteIdentification:
    is_ransom_note: bool = False
    family: Optional[str] = None
    provenance: Optional[str] = None
    matched_on: list = field(default_factory=list)   # "note_name" and/or "note_content"
    generic_markers: list = field(default_factory=list)
    path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_ransom_note": self.is_ransom_note,
            "family": self.family,
            "provenance": self.provenance,
            "matched_on": self.matched_on,
            "generic_markers": self.generic_markers,
            "path": self.path,
        }


def identify(filename: str, text: str) -> NoteIdentification:
    """Classify a candidate note by its filename and content. Family attribution requires
    either a distinctive note filename OR matching template markers -- generic note names
    alone never assert a family."""
    name = os.path.basename(filename)
    low = text.lower()

    # The filename hint only selects candidates worth reading -- it must NOT by itself brand
    # a file a ransom note (a benign readme.txt would trip it). The decision is content-based
    # (enough generic markers) or a positive family match.
    generic = [m for m in _GENERIC_MARKERS if m in low]
    is_note = len(generic) >= _MIN_GENERIC_HITS

    best = None
    for fam in FAMILIES:
        matched = []
        if fam.note_name_regex and re.search(fam.note_name_regex, name, re.IGNORECASE):
            matched.append("note_name")
        if fam.note_markers and all(mk.lower() in low for mk in fam.note_markers):
            matched.append("note_content")
        if matched:
            # prefer a content match (strongest) over a name-only match
            score = (2 if "note_content" in matched else 0) + (1 if "note_name" in matched else 0)
            if best is None or score > best[0]:
                best = (score, fam, matched)

    if best:
        _, fam, matched = best
        return NoteIdentification(
            is_ransom_note=True, family=fam.name, provenance=fam.provenance,
            matched_on=matched, generic_markers=generic, path=filename)
    return NoteIdentification(is_ransom_note=is_note, generic_markers=generic, path=filename)


def identify_path(path: str) -> NoteIdentification:
    try:
        with open(path, "rb") as f:
            raw = f.read(_NOTE_MAX_BYTES)
        text = raw.decode("utf-8", errors="ignore")
    except OSError:
        return NoteIdentification(path=path)
    return identify(path, text)


def looks_like_note_name(name: str) -> bool:
    return bool(_NOTE_NAME_HINTS.search(os.path.basename(name)))


def find_notes(root: str, max_notes: int = 500) -> List[NoteIdentification]:
    """Walk `root` for likely ransom-note files (small text files whose names match the
    hints), classify each, and return those that are ransom notes. Capped for very large
    trees; de-duplicates identical note contents by (family, matched_on, first line)."""
    found = []
    seen = set()
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            if len(found) >= max_notes:
                return found
            if not looks_like_note_name(name):
                continue
            fp = os.path.join(dirpath, name)
            try:
                if os.path.getsize(fp) > _NOTE_MAX_BYTES:
                    continue
            except OSError:
                continue
            ident = identify_path(fp)
            if not ident.is_ransom_note:
                continue
            key = (ident.family, tuple(ident.matched_on), name.lower())
            if key in seen:
                continue
            seen.add(key)
            found.append(ident)
    return found


def families_seen(notes: List[NoteIdentification]) -> dict:
    """Aggregate identified families across a list of note identifications."""
    from collections import Counter
    c = Counter(n.family for n in notes if n.family)
    return dict(c.most_common())
