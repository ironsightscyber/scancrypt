"""Evidence-integrity layer: hash-chained audit log, before/after proof, case metadata."""
import hashlib
import json
from datetime import datetime, timezone

import pytest

from rprt import forensics, report, engine


class _Clock:
    """Deterministic monotonically-increasing UTC clock for reproducible logs."""
    def __init__(self):
        self.t = 0

    def __call__(self):
        self.t += 1
        return datetime(2026, 1, 1, 0, 0, self.t, tzinfo=timezone.utc)


def test_sha256_file_matches_hashlib(tmp_path):
    data = b"evidence bytes " * 5000
    p = tmp_path / "e.bin"
    p.write_bytes(data)
    assert forensics.sha256_file(str(p)) == hashlib.sha256(data).hexdigest()


def test_audit_log_records_chain(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    case = forensics.CaseContext(case_id="IR-1", examiner="RB", evidence_id="E1")
    audit = forensics.AuditLog(path=str(log_path), case=case, now=_Clock())
    audit.input_opened("/evidence/disk.img", sha256="a" * 64)
    audit.record("scan_complete", pattern="front-only")
    audit.session_end()

    result = forensics.verify_log(str(log_path))
    assert result["ok"] is True
    assert result["entries"] == 4          # session_start, input_opened, scan_complete, session_end
    assert result["seal"] == audit.seal()


def test_tamper_breaks_the_chain(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = forensics.AuditLog(path=str(log_path), now=_Clock())
    audit.record("scan_complete", pattern="front-only", recoverable_pct=90.0)
    audit.session_end()
    assert forensics.verify_log(str(log_path))["ok"]

    # tamper: flip a recorded value in the middle entry, leave its hash as-is
    lines = log_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["recoverable_pct"] = 10.0        # attacker downgrades the finding
    lines[1] = json.dumps(entry)
    log_path.write_text("\n".join(lines) + "\n")

    verdict = forensics.verify_log(str(log_path))
    assert verdict["ok"] is False
    assert verdict["broken_at"] == 1


def test_deleted_entry_breaks_the_chain(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = forensics.AuditLog(path=str(log_path), now=_Clock())
    audit.record("a", x=1)
    audit.record("b", x=2)
    audit.session_end()

    lines = log_path.read_text().splitlines()
    del lines[2]                            # remove an entry from the middle
    log_path.write_text("\n".join(lines) + "\n")
    assert forensics.verify_log(str(log_path))["ok"] is False


def test_integrity_verified_records_match(tmp_path):
    audit = forensics.AuditLog(now=_Clock())
    h = "b" * 64
    entry = audit.integrity_verified("/evidence/x", before=h, after=h)
    assert entry["unchanged"] is True
    entry2 = audit.integrity_verified("/evidence/x", before=h, after="c" * 64)
    assert entry2["unchanged"] is False


def test_case_metadata_in_html_report(tmp_path):
    import random
    rng = random.Random(1)
    p = tmp_path / "s.bin"
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(1024 * 1024)) + b"text " * 400000)
    rep = engine.scan(str(p))
    case = forensics.CaseContext(case_id="CASE-0001", examiner="A. Analyst",
                                 evidence_id="DISK-01").to_dict()
    doc = report.build_html_report(str(p), rep, case=case)
    assert "CASE-0001" in doc
    assert "A. Analyst" in doc
    assert "DISK-01" in doc
    assert "<h2>Case</h2>" in doc


def test_no_case_section_when_absent(tmp_path):
    import random
    rng = random.Random(2)
    p = tmp_path / "s.bin"
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(4096)))
    rep = engine.scan(str(p))
    doc = report.build_html_report(str(p), rep)
    assert "<h2>Case</h2>" not in doc


def test_verify_log_missing_file():
    assert forensics.verify_log("/nonexistent/audit.jsonl")["ok"] is False
