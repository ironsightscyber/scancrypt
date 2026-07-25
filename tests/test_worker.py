"""Worker protocol (rprt.worker): the JSONL contract between the GUI supervisor and the
recovery child process."""
import io
import json
import os

from rprt import worker


def test_emitter_silent_when_not_jsonl():
    buf = io.StringIO()
    em = worker.Emitter(buf, jsonl=False)
    em.emit("started", reader="x")
    assert buf.getvalue() == ""


def test_emitter_one_object_per_line_with_version():
    buf = io.StringIO()
    em = worker.Emitter(buf, jsonl=True)
    em.emit("started", reader="vhdx-recovered")
    em.emit("progress", fraction=0.5, files_recovered=3)
    lines = buf.getvalue().splitlines()
    assert len(lines) == 2
    a = json.loads(lines[0])
    assert a == {"v": 1, "type": "started", "reader": "vhdx-recovered"}
    b = json.loads(lines[1])
    assert b["type"] == "progress" and b["files_recovered"] == 3


def test_parse_line_ignores_blank_and_malformed():
    assert worker.parse_line("") is None
    assert worker.parse_line("   ") is None
    assert worker.parse_line("not json") is None
    assert worker.parse_line(json.dumps({"no": "type"})) is None
    ev = worker.parse_line(json.dumps({"v": 1, "type": "completed", "files_recovered": 4}))
    assert ev["type"] == "completed" and ev["files_recovered"] == 4


def test_write_summary_persists_to_disk(tmp_path):
    p = worker.write_summary(str(tmp_path), {"files_recovered": 2, "files_failed": 0})
    assert os.path.exists(p)
    with open(p) as f:
        data = json.load(f)
    assert data["v"] == 1 and data["files_recovered"] == 2


def test_redact_disk_name_strips_victim_identifiers():
    assert worker.redact_disk_name(
        "Payroll Database.vhdx.[AB12CD34].[attacker@example.org].ndm448"
    ) == "*.vhdx.ndm448"
    assert worker.redact_disk_name("C:/vm/disk.vmdk") == "*.vmdk"
    assert worker.redact_disk_name("plain.img") == "*.img"


def test_diaglog_writes_no_paths_by_default(tmp_path):
    log = tmp_path / "d.log"
    d = worker.DiagLog(str(log), verbose=False)
    d.section("start")
    d.kv(reader="vhdx-recovered", geometry_block=33554432)
    d.line("WARN corrupt record")
    d.close()
    text = log.read_text()
    assert "reader: vhdx-recovered" in text and "corrupt record" in text
    assert d.verbose is False
