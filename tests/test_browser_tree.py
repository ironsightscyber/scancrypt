"""The lazy, TreeSize-style volume browser (rprt.gui.VolumeBrowserDialog).

Drives the real dialog with a QApplication, but replaces the two child processes it spawns
(the --serve dir-server and the --list-volume scan) with tiny fakes, so the test is
deterministic and needs no real disk. Skipped where PySide6 can't create an application
(headless CI without the Qt platform libs)."""
import sys
import time

import pytest

FAKE_SERVE = """
import json, sys
TREE = {
  "/": [("Users",True,None),("Windows",True,None)],
  "/Users": [("austec",True,None),("Public",True,None)],
  "/Users/austec": [("report.mdf",False,1000),("notes.txt",False,50)],
  "/Users/Public": [],
  "/Windows": [("win.dll",False,200)],
}
def e(**k): print(json.dumps({"v":1, **k}), flush=True)
e(type="ready", reader="raw", base=0)
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    req = json.loads(line); op = req.get("op"); rid = req.get("id"); path = req.get("path","/")
    if op == "close": break
    if op == "listdir":
        ents = [{"name":n,"path":path.rstrip('/')+'/'+n,"is_dir":d,"size":s}
                for (n,d,s) in TREE.get(path, [])]
        e(type="listing", id=rid, path=path, entries=ents)
    elif op == "listtree":
        files = []; stack = [path]
        while stack:
            p = stack.pop()
            for (n,d,s) in TREE.get(p, []):
                cp = p.rstrip('/')+'/'+n
                (stack.append(cp) if d else files.append([cp,s]))
        e(type="tree", id=rid, path=path, files=files, truncated=False)
    else:
        e(type="op_error", id=rid, message="unknown op")
"""

FAKE_LIST = """
import json, sys
def e(**k): print(json.dumps({"v":1, **k}), flush=True)
e(type="started", reader="raw")
for p, s in [("/Users/austec/report.mdf",1000),("/Users/austec/notes.txt",50),("/Windows/win.dll",200)]:
    e(type="file", path=p, size=s)
e(type="completed", files=3)
"""


def _app_or_skip():
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PySide6 not importable: {exc}")
    try:
        return QApplication.instance() or QApplication([])
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"cannot create QApplication (headless): {exc}")


def _wait(app, cond, secs=15):
    end = time.time() + secs
    while time.time() < end and not cond():
        app.processEvents()
        time.sleep(0.01)
    return cond()


def test_lazy_tree_browser(tmp_path, monkeypatch):
    app = _app_or_skip()
    from rprt import gui, supervise

    (tmp_path / "srv.py").write_text(FAKE_SERVE)
    (tmp_path / "lst.py").write_text(FAKE_LIST)
    monkeypatch.setattr(supervise, "_serve_argv",
                        lambda disk: [sys.executable, str(tmp_path / "srv.py")])
    monkeypatch.setattr(supervise, "_list_argv",
                        lambda disk, min_size=0: [sys.executable, str(tmp_path / "lst.py")])

    dlg = gui.VolumeBrowserDialog(None, "fake.vhdx")
    try:
        # 1. the root loads without a full scan (lazy)
        assert _wait(app, lambda: dlg.tree.topLevelItemCount() > 0), "root never loaded"
        roots = [dlg.tree.topLevelItem(i).text(0) for i in range(dlg.tree.topLevelItemCount())]
        assert roots == ["Users", "Windows"]

        # 2. expanding a folder reads only that folder
        users = dlg.tree.topLevelItem(0)
        users.setExpanded(True)
        assert _wait(app, lambda: users.childCount() > 1), "expand did not load children"
        kids = [(users.child(i).text(0), bool(users.child(i).data(0, dlg.ISDIR_ROLE)))
                for i in range(users.childCount())]
        assert kids == [("austec", True), ("Public", True)]

        austec = users.child(0)
        austec.setExpanded(True)
        assert _wait(app, lambda: austec.childCount() > 1)
        assert austec.child(0).text(0) == "report.mdf"
        assert austec.child(0).text(1) == gui.human_bytes(1000)

        # 3. the scan is opt-in: search/sizes are off until requested, then it fills them in
        assert not dlg._scan_done and not dlg.search.isEnabled()
        assert dlg.scan_btn.isEnabled()          # enabled once the volume opened
        dlg._begin_scan()                        # user clicks "Scan for sizes & search"
        assert _wait(app, lambda: dlg._scan_done), "scan never completed"
        assert users.text(1) == gui.human_bytes(1050)          # 1000 + 50
        assert dlg.tree.topLevelItem(1).text(1) == gui.human_bytes(200)
        assert dlg.search.isEnabled()

        # 4. search switches to a flat, whole-volume result view
        dlg.search.setText("mdf")
        app.processEvents()
        assert dlg.stack.currentIndex() == 1 and dlg.model.rowCount() == 1
        dlg.search.setText("")
        app.processEvents()
        assert dlg.stack.currentIndex() == 0                    # back to the tree

        # 5. selecting a folder enumerates its whole subtree for extraction
        austec.setSelected(True)
        app.processEvents()
        files, dirs = dlg._selection()
        assert dirs == ["/Users/austec"] and dlg.extract_btn.isEnabled()

        captured = {}
        import types
        dlg._launch_extract = types.MethodType(
            lambda self: captured.setdefault("paths", sorted(self._extract_files)), dlg)
        dlg._extract_files, dlg._extract_dirs = [], ["/Users/austec"]
        dlg._drain_dirs()
        assert _wait(app, lambda: "paths" in captured, 5), "folder enumeration never finished"
        assert captured["paths"] == ["/Users/austec/notes.txt", "/Users/austec/report.mdf"]
    finally:
        dlg.reject()
        _wait(app, lambda: False, 0.3)


FAKE_RECOVER = """
import json, sys
def e(**k): print(json.dumps({"v":1, **k}), flush=True)
e(type="started", reader="raw")
e(type="completed", files_recovered=1, files_failed=0, bytes_written=42, reader="raw")
sys.exit(0)
"""


def test_extract_runs_on_ui_thread_no_cross_thread_access(tmp_path, monkeypatch):
    """Regression: worker signals must connect to bound methods, not bare lambdas. A lambda
    slot runs in the worker thread, so _on_extracted would open its modal QMessageBox there --
    a cross-thread widget access that froze the app mid-extract. Assert Qt emits no
    'different thread' / 'Cannot set parent' warning while a real extraction completes."""
    app = _app_or_skip()
    from rprt import gui, supervise
    from PySide6.QtCore import qInstallMessageHandler
    from PySide6.QtWidgets import QMessageBox, QFileDialog

    (tmp_path / "srv.py").write_text(FAKE_SERVE)
    (tmp_path / "lst.py").write_text(FAKE_LIST)
    (tmp_path / "rec.py").write_text(FAKE_RECOVER)
    monkeypatch.setattr(supervise, "_serve_argv",
                        lambda disk: [sys.executable, str(tmp_path / "srv.py")])
    monkeypatch.setattr(supervise, "_list_argv",
                        lambda disk, min_size=0: [sys.executable, str(tmp_path / "lst.py")])
    monkeypatch.setattr(supervise, "_worker_argv",
                        lambda *a, **k: [sys.executable, str(tmp_path / "rec.py")])
    dest = tmp_path / "out"
    dest.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: str(dest)))
    monkeypatch.setattr(QMessageBox, "exec", lambda self, *a, **k: 0)

    msgs = []
    qInstallMessageHandler(lambda mode, ctx, message: msgs.append(message))
    try:
        dlg = gui.VolumeBrowserDialog(None, "fake.vhdx")
        try:
            assert _wait(app, lambda: dlg.tree.topLevelItemCount() > 0)
            users = dlg.tree.topLevelItem(0)
            users.setExpanded(True)
            assert _wait(app, lambda: users.childCount() > 1)
            austec = users.child(0)
            austec.setExpanded(True)
            assert _wait(app, lambda: austec.childCount() > 1)
            report = next(austec.child(i) for i in range(austec.childCount())
                          if not austec.child(i).data(0, dlg.ISDIR_ROLE))
            report.setSelected(True)
            app.processEvents()
            dlg._extract_selected()                      # real extract path (bound-method slots)
            assert _wait(app, lambda: not dlg._busy, 15), "extraction never completed"
        finally:
            dlg.reject()
            _wait(app, lambda: False, 0.3)
    finally:
        qInstallMessageHandler(None)

    cross = [m for m in msgs if "different thread" in m or "Cannot set parent" in m]
    assert not cross, f"cross-thread widget access during extract: {cross}"


def test_browser_reports_missing_volume(tmp_path, monkeypatch):
    """A child that finds no volume is surfaced as a clean message, not a crash."""
    app = _app_or_skip()
    from rprt import gui, supervise

    (tmp_path / "srv.py").write_text(
        'import json,sys\n'
        'print(json.dumps({"v":1,"type":"fatal","code":"NO_VOLUME","message":"none"}),flush=True)\n'
        'sys.exit(2)\n')
    (tmp_path / "lst.py").write_text(
        'import json\nprint(json.dumps({"v":1,"type":"fatal","code":"NO_VOLUME"}),flush=True)\n')
    monkeypatch.setattr(supervise, "_serve_argv",
                        lambda disk: [sys.executable, str(tmp_path / "srv.py")])
    monkeypatch.setattr(supervise, "_list_argv",
                        lambda disk, min_size=0: [sys.executable, str(tmp_path / "lst.py")])

    dlg = gui.VolumeBrowserDialog(None, "fake.vhdx")
    try:
        assert _wait(app, lambda: "No readable NTFS" in dlg.status.text())
        assert dlg.tree.topLevelItemCount() == 0
    finally:
        dlg.reject()
        _wait(app, lambda: False, 0.3)
