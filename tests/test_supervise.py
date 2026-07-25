"""Process supervisor (rprt.supervise): the guarantee that a crash in the recovery child is
reported as a clean outcome and never propagates to the parent."""
import os
import sys
import textwrap

import pytest

from rprt import supervise


def _run_with_worker(tmp_path, script_body, cancel_check=None):
    """Run supervise.recover with the child replaced by a tiny inline worker script."""
    script = tmp_path / "worker.py"
    script.write_text(textwrap.dedent(script_body))
    orig = supervise._worker_argv
    supervise._worker_argv = lambda *a, **k: [sys.executable, str(script)]
    try:
        events = []
        out = supervise.recover("disk.vhdx", str(tmp_path / "out"),
                                on_event=events.append, cancel_check=cancel_check)
        return out, events
    finally:
        supervise._worker_argv = orig


def test_completed_outcome(tmp_path):
    out, events = _run_with_worker(tmp_path, """
        import json, sys
        def e(**k): print(json.dumps({"v":1, **k}), flush=True)
        e(type="started", reader="vhdx-recovered")
        e(type="file_recovered", path="/a.db", bytes_written=100)
        e(type="completed", files_recovered=1, files_failed=0, bytes_written=100, reader="vhdx-recovered")
        sys.exit(0)
    """)
    assert out["status"] == "completed"
    assert out["files_recovered"] == 1 and out["bytes_written"] == 100
    assert {e["type"] for e in events} >= {"started", "completed"}


def test_crash_is_contained(tmp_path):
    out, _ = _run_with_worker(tmp_path, """
        import json, os
        print(json.dumps({"v":1,"type":"started","reader":"raw"}), flush=True)
        os.abort()          # abnormal exit, no 'completed'
    """)
    assert out["status"] == "crashed"          # parent survives, classified cleanly
    assert out["exit_code"] != 0


def test_no_volume_exit_code(tmp_path):
    out, _ = _run_with_worker(tmp_path, """
        import json, sys
        print(json.dumps({"v":1,"type":"fatal","code":"NO_VOLUME","message":"none"}), flush=True)
        sys.exit(2)
    """)
    assert out["status"] == "no_volume"


def test_cancellation_terminates_child(tmp_path):
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 2      # request cancel after a couple of polls

    out, _ = _run_with_worker(tmp_path, """
        import time, json
        print(json.dumps({"v":1,"type":"started","reader":"raw"}), flush=True)
        time.sleep(30)             # would hang without cancellation
    """, cancel_check=cancel)
    assert out["status"] == "cancelled"


def test_worker_argv_dev_mode():
    argv = supervise._worker_argv("d.vhdx", "/out", 1000)
    assert argv[:3] == [sys.executable, "-m", "rprt"]
    assert "--recover-files" in argv and "--jsonl" in argv
    assert "--min-file-size" in argv


def _run_list_with_worker(tmp_path, script_body, cancel_check=None):
    script = tmp_path / "lister.py"
    script.write_text(textwrap.dedent(script_body))
    orig = supervise._list_argv
    supervise._list_argv = lambda *a, **k: [sys.executable, str(script)]
    try:
        files = []
        out = supervise.list_files("disk.vhdx", on_file=lambda ev: files.append(ev),
                                   cancel_check=cancel_check)
        return out, files
    finally:
        supervise._list_argv = orig


def test_list_files_streams_and_completes(tmp_path):
    out, files = _run_list_with_worker(tmp_path, """
        import json, sys
        def e(**k): print(json.dumps({"v":1, **k}), flush=True)
        e(type="started", reader="vhdx-recovered")
        e(type="file", path="/a.db", size=100)
        e(type="file", path="/dir/b.txt", size=5)
        e(type="completed", files=2)
        sys.exit(0)
    """)
    assert out["status"] == "completed" and out["files"] == 2
    assert [f["path"] for f in files] == ["/a.db", "/dir/b.txt"]


def test_list_files_crash_contained(tmp_path):
    out, _ = _run_list_with_worker(tmp_path, """
        import json, os
        print(json.dumps({"v":1,"type":"started","reader":"raw"}), flush=True)
        os.abort()
    """)
    assert out["status"] == "crashed"


# ---------------------------------------------------------------- DirServer (lazy browse tree)

def _serve_with_script(tmp_path, script_body):
    """Install a fake --serve child that speaks the request/response protocol; returns the
    opened DirServer. Caller must srv.close()."""
    script = tmp_path / "srv.py"
    script.write_text(textwrap.dedent(script_body))
    orig = supervise._serve_argv
    supervise._serve_argv = lambda *a, **k: [sys.executable, str(script)]
    try:
        return supervise.DirServer("disk.vhdx").open(timeout=30)
    finally:
        supervise._serve_argv = orig


_FAKE_SERVE = """
    import json, sys
    def e(**k): print(json.dumps({"v":1, **k}), flush=True)
    e(type="ready", reader="vhdx-recovered", base=123)
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        req = json.loads(line); op = req.get("op"); rid = req.get("id")
        if op == "close": break
        if op == "listdir":
            e(type="listing", id=rid, path=req.get("path"),
              entries=[{"name":"a.db","path":"/a.db","is_dir":False,"size":10},
                       {"name":"sub","path":"/sub","is_dir":True,"size":None}])
        elif op == "listtree":
            e(type="tree", id=rid, path=req.get("path"),
              files=[["/sub/x",5],["/sub/y",7]], truncated=False)
        else:
            e(type="op_error", id=rid, message="unknown op")
    sys.exit(0)
"""


def test_dirserver_ready_and_listdir(tmp_path):
    srv = _serve_with_script(tmp_path, _FAKE_SERVE)
    try:
        assert srv.status == "ready"
        assert srv.reader == "vhdx-recovered" and srv.base == 123
        entries, err = srv.list_dir("/")
        assert err is None
        assert [e["name"] for e in entries] == ["a.db", "sub"]
        files, truncated, err = srv.list_tree("/sub")
        assert err is None and truncated is False
        assert files == [["/sub/x", 5], ["/sub/y", 7]]
    finally:
        srv.close()
    assert srv.status == "dead"
    # a request after close returns an error instead of hanging
    _, err = srv.list_dir("/")
    assert err


def test_dirserver_no_volume(tmp_path):
    srv = _serve_with_script(tmp_path, """
        import json, sys
        print(json.dumps({"v":1,"type":"fatal","code":"NO_VOLUME","message":"none"}), flush=True)
        sys.exit(2)
    """)
    try:
        assert srv.status == "no_volume"
    finally:
        srv.close()


def test_dirserver_crash_is_contained(tmp_path):
    srv = _serve_with_script(tmp_path, """
        import json, os, sys
        print(json.dumps({"v":1,"type":"ready","reader":"raw","base":0}), flush=True)
        for line in sys.stdin:
            os.abort()          # die on the first request
    """)
    try:
        assert srv.status == "ready"
        entries, err = srv.list_dir("/")     # child dies mid-request
        assert entries is None and err       # reported cleanly, no exception
        assert srv.status == "dead"
    finally:
        srv.close()


def test_serve_argv_dev_mode():
    argv = supervise._serve_argv("d.vhdx")
    assert argv[:3] == [sys.executable, "-m", "rprt"]
    assert argv[-2:] == ["d.vhdx", "--serve"]
