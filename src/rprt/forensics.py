"""rprt.forensics — evidence-integrity layer for court/insurance-grade recovery work.

Three things an IR deliverable needs that a hobby carver skips:

  1. Proof the tool never modified the evidence -- the input's SHA-256 recorded before AND
     after the session, shown to match. (Everything in rprt is read-only, so they always
     will; the point is to *prove* it, not assume it.)
  2. A tamper-evident audit trail -- every operation, timestamped, with the offsets/paths
     touched and the hashes of inputs and outputs, as a hash-chained JSONL log: each entry
     carries the hash of the previous one, so any later edit, deletion, or reorder breaks
     the chain and is detectable.
  3. Case metadata -- case id, examiner, evidence id -- bound into the log and the report.

Read-only against evidence. The audit log and any outputs go to caller-chosen paths.
"""
from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__
from .source import open_source

GENESIS = "0" * 64   # prev-hash of the first entry


@dataclass
class CaseContext:
    case_id: str = ""
    examiner: str = ""
    evidence_id: str = ""
    description: str = ""
    organization: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def sha256_file(path: str, chunk_size: int = 8 * 1024 * 1024,
                progress=None, cancel_check=None) -> str:
    """Stream a whole input through SHA-256, read-only, via the source abstraction (so it
    works on files, images, and raw devices alike)."""
    h = hashlib.sha256()
    with open_source(path) as src:
        size = src.size
        off = 0
        while off < size:
            if cancel_check is not None and cancel_check():
                raise KeyboardInterrupt("hashing cancelled")
            b = src.read_at(off, min(chunk_size, size - off))
            if not b:
                break
            h.update(b)
            off += len(b)
            if progress:
                progress(off / max(size, 1), "Hashing")
    return h.hexdigest()


def _entry_hash(entry: dict) -> str:
    """Deterministic hash over an entry, excluding the 'hash' field itself."""
    payload = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """A hash-chained, append-only audit trail. Each record() appends one JSONL line whose
    hash covers its own content plus the previous entry's hash, making the log tamper-
    evident. `now` is injectable for deterministic tests."""

    def __init__(self, path: Optional[str] = None, case: Optional[CaseContext] = None,
                 now=None):
        self.path = path
        self.case = case or CaseContext()
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.entries: List[dict] = []
        self._prev = GENESIS
        if path:
            # truncate/create so a session starts a fresh chain
            open(path, "w").close()
        self.record("session_start", tool="ScanCrypt", version=__version__,
                    platform=platform.platform(), case=self.case.to_dict())

    def record(self, event: str, **fields) -> dict:
        entry = {
            "seq": len(self.entries),
            "ts": self._now().isoformat(),
            "event": event,
            "prev": self._prev,
        }
        entry.update(fields)
        entry["hash"] = _entry_hash(entry)
        self._prev = entry["hash"]
        self.entries.append(entry)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def seal(self) -> str:
        """The current chain head -- the single value that fixes the whole log. Record it
        externally (e.g. in the report) and anyone can later verify the log against it."""
        return self._prev

    # -- convenience recorders -------------------------------------------------

    def input_opened(self, path: str, sha256: Optional[str] = None) -> dict:
        import os
        size = None
        try:
            size = os.path.getsize(path)
        except OSError:
            pass
        return self.record("input_opened", path=path, size=size, sha256=sha256,
                           access="read-only")

    def output_written(self, path: str, bytes_written: int, sha256: Optional[str] = None) -> dict:
        return self.record("output_written", path=path, bytes=bytes_written, sha256=sha256)

    def integrity_verified(self, path: str, before: str, after: str) -> dict:
        return self.record("integrity_verified", path=path, sha256_before=before,
                           sha256_after=after, unchanged=(before == after))

    def session_end(self) -> dict:
        entry = self.record("session_end")
        # seal after the terminal entry so it fixes the entire chain including session_end
        return entry


def verify_log(path: str) -> dict:
    """Re-read a JSONL audit log and verify the hash chain: each entry's hash must match
    its content, and its 'prev' must equal the previous entry's hash. Returns
    {ok, entries, broken_at?, reason?}."""
    prev = GENESIS
    n = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("prev") != prev:
                    return {"ok": False, "entries": n, "broken_at": i,
                            "reason": "prev-hash does not chain to previous entry"}
                if _entry_hash(entry) != entry.get("hash"):
                    return {"ok": False, "entries": n, "broken_at": i,
                            "reason": "entry hash does not match its content"}
                prev = entry["hash"]
                n += 1
    except (OSError, ValueError) as exc:
        return {"ok": False, "entries": n, "reason": str(exc)}
    return {"ok": True, "entries": n, "seal": prev}
