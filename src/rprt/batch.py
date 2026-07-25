"""rprt.batch — incident-level triage across a directory tree of encrypted files.

A ransomware incident hits a *share*, not one file. This walks a directory, runs the
single-file scan on each file, and aggregates the answer the victim actually needs on day
one: "across N files totalling X, this fraction is recoverable for free" -- the concrete,
evidenced number that removes ransom-payment leverage before anyone considers paying.

Composes the rest of rprt: each file is scanned (boundary/adaptive), classified, family-
fingerprinted, and format-detected. Read-only throughout. Per-file hashing is optional
(slow at scale) for an evidence-grade manifest.
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import engine

ProgressFn = Optional[Callable[[float, str], None]]


@dataclass
class FileResult:
    path: str
    size: int
    pattern: str = ""
    recoverable_bytes: int = 0
    recoverable_pct: float = 0.0
    family: Optional[str] = None
    formats: list = field(default_factory=list)
    sha256: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path, "size": self.size, "pattern": self.pattern,
            "recoverable_bytes": self.recoverable_bytes,
            "recoverable_pct": self.recoverable_pct,
            "family": self.family, "formats": [f["name"] for f in self.formats],
            "sha256": self.sha256, "error": self.error,
        }


@dataclass
class BatchResult:
    root: str
    files: list = field(default_factory=list)   # list[FileResult]
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    notes: list = field(default_factory=list)   # list[ransomnote.NoteIdentification]

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    @property
    def recoverable_bytes(self) -> int:
        return sum(f.recoverable_bytes for f in self.files)

    @property
    def recoverable_pct(self) -> float:
        tb = self.total_bytes
        return round(100 * self.recoverable_bytes / tb, 2) if tb else 0.0

    def pattern_breakdown(self) -> dict:
        c = Counter(f.pattern for f in self.files if f.pattern)
        return dict(c.most_common())

    def bytes_by_pattern(self) -> dict:
        out = Counter()
        for f in self.files:
            if f.pattern:
                out[f.pattern] += f.size
        return dict(out.most_common())

    def family_breakdown(self) -> dict:
        c = Counter(f.family for f in self.files if f.family)
        return dict(c.most_common())

    def note_families(self) -> dict:
        from . import ransomnote
        return ransomnote.families_seen(self.notes)

    def identified_strain(self) -> Optional[str]:
        """Best single strain name for the incident: a note-confirmed family if any,
        else the most common family seen across encrypted files."""
        nf = self.note_families()
        if nf:
            return next(iter(nf))
        fb = self.family_breakdown()
        return next(iter(fb)) if fb else None

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "scanned": self.scanned, "skipped": self.skipped, "errors": self.errors,
            "total_bytes": self.total_bytes,
            "recoverable_bytes": self.recoverable_bytes,
            "recoverable_pct": self.recoverable_pct,
            "pattern_breakdown": self.pattern_breakdown(),
            "bytes_by_pattern": self.bytes_by_pattern(),
            "family_breakdown": self.family_breakdown(),
            "ransom_notes_found": len(self.notes),
            "note_families": self.note_families(),
            "identified_strain": self.identified_strain(),
            "files": [f.to_dict() for f in self.files],
        }


def _iter_files(root: str, min_size: int):
    for dirpath, _dirs, filenames in os.walk(root):
        for name in sorted(filenames):
            fp = os.path.join(dirpath, name)
            try:
                if not os.path.isfile(fp) or os.path.islink(fp):
                    continue
                size = os.path.getsize(fp)
            except OSError:
                continue
            if size < max(min_size, 1):
                continue
            yield fp, size


def scan_tree(root: str, min_size: int = 1, full: bool = False, do_hash: bool = False,
              progress: ProgressFn = None, cancel_check=None) -> BatchResult:
    """Scan every regular file under `root` (>= min_size bytes) and aggregate. Per-file
    errors are recorded, never fatal. Read-only."""
    result = BatchResult(root=root)

    # Ransom-note sweep first: identifying the strain up front sets expectations for the
    # per-file scan and gives the incident report a confirmed family name.
    try:
        from . import ransomnote
        result.notes = ransomnote.find_notes(root)
    except Exception:  # noqa: BLE001 -- advisory
        result.notes = []

    files = list(_iter_files(root, min_size))
    total = len(files) or 1

    for i, (fp, size) in enumerate(files):
        if cancel_check is not None and cancel_check():
            break
        if progress:
            progress(i / total, os.path.basename(fp))
        fr = FileResult(path=fp, size=size)
        try:
            report = engine.scan(fp, full=full)
            fr.pattern = report.pattern
            fr.recoverable_bytes = report.recoverable_bytes
            fr.recoverable_pct = report.recoverable_pct
            fr.family = report.family["family"] if report.family else None
            fr.formats = report.formats
            if do_hash:
                from .report import sha256_of_input
                fr.sha256 = sha256_of_input(fp)
            result.scanned += 1
        except Exception as exc:  # noqa: BLE001 -- one bad file can't stop the incident scan
            fr.error = str(exc)
            result.errors += 1
        result.files.append(fr)

    if progress:
        progress(1.0, "Done")
    return result


def write_csv(result: BatchResult, out_path: str) -> str:
    """Write a per-file CSV: path, size, pattern, recoverable %, recoverable bytes,
    family, formats, sha256, error."""
    import csv

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["path", "size_bytes", "pattern", "recoverable_pct",
                    "recoverable_bytes", "family", "formats", "sha256", "error"])
        for fr in result.files:
            w.writerow([fr.path, fr.size, fr.pattern, fr.recoverable_pct,
                        fr.recoverable_bytes, fr.family or "",
                        "; ".join(x["name"] for x in fr.formats),
                        fr.sha256 or "", fr.error or ""])
    return out_path
