"""rprt.gui — PySide6 desktop front-end.

Scan and extraction run on a worker QThread so the UI stays responsive on
100+ GB files; the worker reports fractional progress and can be cancelled
mid-scan. Nothing here writes to the input file -- only to a user-chosen
output path for extraction.
"""
from __future__ import annotations

import faulthandler
import sys
from pathlib import Path

# Native-crash traceback backstop. A windowed (no-console) frozen build has sys.stderr = None,
# and faulthandler.enable() would raise "sys.stderr is None" at import -- so guard it. The GUI
# process is only a supervisor now; the child that parses untrusted disks keeps its own
# faulthandler (pointed at the diagnostic log), which is where a crash trace actually matters.
if sys.stderr is not None:
    faulthandler.enable()

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QColor, QDesktopServices, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QStackedWidget,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from . import engine
from . import report as report_mod

PATTERN_COLORS = {
    "front-only": "#2e7d32",
    "fully-intact": "#2e7d32",
    "periodic-intermittent": "#e65100",
    "scattered-benign": "#2e7d32",
    "compressed-benign": "#2e7d32",
    "mixed": "#e65100",
    "non-contiguous": "#e65100",
    "fully-encrypted": "#c62828",
}

_STRIP_KIND_COLORS = {
    "encrypted": QColor(report_mod.STRIP_ENCRYPTED),
    "intact": QColor(report_mod.STRIP_INTACT),
    "zero": QColor(report_mod.STRIP_ZERO),
}


class EntropyStripWidget(QWidget):
    """A horizontal band across the file coloured by what each region reads as --
    encrypted / intact / empty. Draws the same segments as the HTML report's SVG
    (via report.entropy_segments), so the app and the exported report agree."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(46)
        self.setMaximumHeight(46)
        self._segments = []
        self._marker = None

    def set_report(self, report):
        self._segments = report_mod.entropy_segments(report) if report else []
        self._marker = report_mod.expected_boundary_fraction(report) if report else None
        self.update()

    def clear(self):
        self._segments = []
        self._marker = None
        self.update()

    def paintEvent(self, event):
        from PySide6.QtCore import Qt as _Qt
        from PySide6.QtGui import QPen
        p = QPainter(self)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor(report_mod.STRIP_BG))
        for x_frac, w_frac, kind in self._segments:
            x = int(round(x_frac * w))
            seg_w = max(int(round(w_frac * w)), 1)
            p.fillRect(x, 0, seg_w, h, _STRIP_KIND_COLORS.get(kind, QColor(report_mod.STRIP_BG)))
        if self._marker is not None:
            mx = int(round(self._marker * w))
            pen = QPen(QColor(report_mod.STRIP_MARKER))
            pen.setStyle(_Qt.DashLine)
            pen.setWidth(2)
            p.setPen(pen)
            p.drawLine(mx, 0, mx, h)
        p.setPen(QColor("#9aa0a6"))
        p.drawRect(0, 0, w - 1, h - 1)


class _CancelToken:
    def __init__(self):
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def __call__(self):
        return self._cancelled


class ScanWorker(QObject):
    progress = Signal(float, str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, path: str, full: bool, cancel_token: _CancelToken):
        super().__init__()
        self.path = path
        self.full = full
        self.cancel_token = cancel_token

    def run(self):
        try:
            report = engine.scan(
                self.path, full=self.full,
                progress=lambda f, label: self.progress.emit(f, label),
                cancel_check=self.cancel_token,
            )
            self.finished.emit(report)
        except engine.Cancelled:
            self.finished.emit(None)
        except Exception as exc:  # noqa: BLE001 -- surface any failure to the UI
            self.failed.emit(str(exc))


class BatchWorker(QObject):
    """Scan a whole folder tree with batch.scan_tree, off the UI thread."""
    progress = Signal(float, str)
    finished = Signal(object)   # BatchResult, or None when cancelled
    failed = Signal(str)

    def __init__(self, root: str, full: bool, cancel_token: _CancelToken):
        super().__init__()
        self.root = root
        self.full = full
        self.cancel_token = cancel_token

    def run(self):
        try:
            from . import batch
            result = batch.scan_tree(
                self.root, full=self.full,
                progress=lambda f, name: self.progress.emit(f, f"Scanning {name}"),
                cancel_check=self.cancel_token)
            self.finished.emit(None if self.cancel_token() else result)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class ExtractWorker(QObject):
    progress = Signal(float, str)
    finished = Signal(int)
    failed = Signal(str)

    def __init__(self, path: str, report: engine.ScanReport, out_path: str,
                 cancel_token: _CancelToken, volume_start=None, volume_length=None):
        super().__init__()
        self.path = path
        self.report = report
        self.out_path = out_path
        self.cancel_token = cancel_token
        self.volume_start = volume_start      # set: cut a volume image instead
        self.volume_length = volume_length

    def run(self):
        try:
            name = Path(self.out_path).name
            if self.volume_start is not None:
                total = self.volume_length or (self.report.size - self.volume_start)
                what = "the NTFS volume image"
            else:
                total = self.report.recoverable_bytes
                what = "the readable bytes"

            def narrate(f, _label):
                self.progress.emit(
                    f, f"Copying {what} into {name} "
                       f"({human_bytes(int(f * total))} of {human_bytes(total)})")

            if self.volume_start is not None:
                written = engine.extract_range(
                    self.path, self.volume_start, self.volume_length, self.out_path,
                    progress=narrate, cancel_check=self.cancel_token)
            else:
                written = engine.extract_intact_ranges(
                    self.path, self.report, self.out_path,
                    progress=narrate, cancel_check=self.cancel_token,
                )
            self.finished.emit(written)
        except engine.Cancelled:
            self.finished.emit(-1)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class NtfsExtractWorker(QObject):
    """Drive volume recovery in a SEPARATE, memory-capped process (see rprt.supervise) so a
    parser crash on a hostile disk can never take down the GUI. This worker only supervises
    and relays progress; it never opens the untrusted disk itself."""
    progress = Signal(float, str)
    finished = Signal(object)   # outcome dict, or None if cancelled
    failed = Signal(str)

    def __init__(self, path, base, dest_dir, min_size, cancel_token, debug=False,
                 only_paths=None):
        super().__init__()
        self.path = path
        self.dest_dir = dest_dir
        self.min_size = min_size
        self.cancel_token = cancel_token
        self.debug = debug
        self.only_paths = only_paths

    def run(self):
        try:
            from . import supervise
            counters = {"ok": 0, "bytes": 0}

            def on_event(ev):
                t = ev.get("type")
                if t == "started":
                    self.progress.emit(0.0, {
                        "vhdx-recovered": "The disk header is encrypted; rebuilding the disk "
                                          "from its surviving block map…",
                        "raw": "Scanning the raw bytes for a valid filesystem…",
                    }.get(ev.get("reader"), "Opening the virtual disk…"))
                elif t == "phase" and ev.get("name") == "extract":
                    self.progress.emit(0.0, "Reading files out of the volume…")
                elif t == "progress":
                    counters["ok"] = ev.get("files_recovered", counters["ok"])
                    counters["bytes"] = ev.get("bytes_written", counters["bytes"])
                    self.progress.emit(
                        ev.get("fraction", 0.0),
                        f"Recovering: {counters['ok']:,} files, {human_bytes(counters['bytes'])}")

            outcome = supervise.recover(
                self.path, self.dest_dir, min_size=self.min_size,
                on_event=on_event, cancel_check=self.cancel_token, debug=self.debug,
                only_paths=self.only_paths)

            status = outcome.get("status")
            if status == "cancelled":
                self.finished.emit(None)
            elif status == "completed":
                self.finished.emit(outcome)
            elif status == "no_volume":
                self.failed.emit(
                    "No readable NTFS filesystem was found inside this virtual disk. The "
                    "encryption likely reached the disk's block map or the volume's start.\n\n"
                    "Best option now:\n• Carve loose files — recovers file contents by "
                    "signature straight from the raw bytes, without needing the disk's "
                    "structure.")
            elif status == "crashed":
                self.failed.emit(
                    "The recovery step stopped on damage this disk's structure could not "
                    "survive. ScanCrypt kept running because that work is isolated in a "
                    "separate process.\n\nAny files recovered before it stopped are already "
                    "in your output folder. For the rest, try Carve loose files.")
            else:  # error
                self.failed.emit(
                    "Recovery could not complete: " + (outcome.get("detail") or "unknown error"))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class VolumeListWorker(QObject):
    """List the volume's files in the supervised child (off the UI thread). Accumulates the
    full list and emits it once at the end -- emitting a signal per file would be 100k+ queued
    cross-thread calls; a running count keeps the dialog responsive meanwhile."""
    progress = Signal(int)          # files found so far
    finished = Signal(object, object, object)   # (outcome, list[(path,size)], folder_sizes)

    def __init__(self, path, cancel_token):
        super().__init__()
        self.path = path
        self.cancel_token = cancel_token

    def run(self):
        from . import supervise
        files = []
        try:
            def on_file(ev):
                files.append((ev.get("path", ""), ev.get("size", 0)))

            def on_event(ev):
                if ev.get("type") == "progress":
                    self.progress.emit(len(files))

            outcome = supervise.list_files(self.path, on_file=on_file, on_event=on_event,
                                           cancel_check=self.cancel_token)
        except Exception as exc:  # noqa: BLE001
            outcome = {"status": "error", "detail": str(exc)}
        # Roll folder sizes up HERE, on this worker thread. Doing it in the finished slot on the
        # UI thread is a ~3M-op loop over a 250k-file disk that stalls the event loop for
        # seconds, and it can land inside the extract-complete modal loop -- which is what froze
        # the window (an unpainted dialog) mid-extract.
        sizes = _folder_sizes(files) if outcome.get("status") in ("completed", "cancelled") else {}
        self.finished.emit(outcome, files, sizes)


class _FileListModel(QAbstractTableModel):
    """A lightweight table of (path, size) with a fast case-insensitive substring filter, so
    it stays responsive over the ~250k files of a full OS disk."""
    _HEADERS = ("File", "Size")

    def __init__(self):
        super().__init__()
        self._all = []
        self._view = []
        self._query = ""

    def set_files(self, files):
        self.beginResetModel()
        self._all = files
        self._apply()
        self.endResetModel()

    def set_query(self, text):
        self.beginResetModel()
        self._query = text.lower().strip()
        self._apply()
        self.endResetModel()

    def _apply(self):
        if not self._query:
            self._view = self._all
        else:
            q = self._query
            self._view = [f for f in self._all if q in f[0].lower()]

    def path_at(self, row):
        return self._view[row][0]

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._view)

    def columnCount(self, parent=QModelIndex()):
        return 2

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        path, size = self._view[index.row()]
        if index.column() == 0:
            return path
        return human_bytes(size)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._HEADERS[section]
        return None


def _folder_sizes(files):
    """Roll every file's size up into all of its ancestor directories: {dir_path: total_bytes}.
    One pass over the flat (path, size) list the background scan already produced, so folder
    sizes cost nothing beyond the scan search needs anyway."""
    sizes = {}
    for path, size in files:
        i = path.rfind("/")
        while i > 0:                       # /a/b/c.txt -> /a/b, then /a
            parent = path[:i]
            sizes[parent] = sizes.get(parent, 0) + size
            i = path.rfind("/", 0, i)
    return sizes


class DirServerWorker(QObject):
    """Owns the persistent DirServer on its own thread, so the untrusted disk is opened once and
    a folder's children are fetched without blocking the UI. The dialog asks for a listing by
    emitting a request signal; the answer returns as a signal tagged with the same request id."""
    ready = Signal(str, str, str)                    # status, reader, detail
    listed = Signal(int, str, object, object)        # req_id, path, entries|None, error|None
    treed = Signal(int, str, object, bool, object)   # req_id, path, files|None, truncated, error

    def __init__(self, disk_path):
        super().__init__()
        self.disk_path = disk_path
        self._srv = None

    @Slot()
    def start(self):
        try:
            from . import supervise
            self._srv = supervise.DirServer(self.disk_path).open()
            self.ready.emit(self._srv.status, self._srv.reader or "", self._srv.detail or "")
        except Exception as exc:  # noqa: BLE001
            self.ready.emit("error", "", str(exc))

    @Slot(int, str)
    def do_listdir(self, req_id, path):
        if self._srv is None:
            self.listed.emit(req_id, path, None, "browser is not running")
            return
        entries, err = self._srv.list_dir(path)
        self.listed.emit(req_id, path, entries, err)

    @Slot(int, str)
    def do_listtree(self, req_id, path):
        if self._srv is None:
            self.treed.emit(req_id, path, None, False, "browser is not running")
            return
        files, truncated, err = self._srv.list_tree(path)
        self.treed.emit(req_id, path, files, truncated, err)

    @Slot()
    def shutdown(self):
        if self._srv is not None:
            self._srv.close()


class VolumeBrowserDialog(QDialog):
    """A lazy, TreeSize-style browser of the recovered volume: the tree opens instantly and a
    folder is read only when it is expanded (rprt.supervise.DirServer). A background scan then
    fills in folder sizes and powers a whole-volume search, so nothing waits on a full read of a
    250k-file disk up front. Extract just the files or folders you pick."""

    PATH_ROLE = Qt.UserRole
    ISDIR_ROLE = Qt.UserRole + 1
    LOADED_ROLE = Qt.UserRole + 2

    _want_listdir = Signal(int, str)
    _want_listtree = Signal(int, str)
    _want_shutdown = Signal()

    def __init__(self, parent, disk_path):
        super().__init__(parent)
        self.disk_path = disk_path
        self.setWindowTitle("Browse volume")
        self.resize(880, 600)

        self._req_id = 0
        self._pending = {}          # req_id -> QTreeWidgetItem awaiting children (None = root)
        self._dir_items = {}        # dir path -> its QTreeWidgetItem, to fill in sizes later
        self._sizes = {}            # dir path -> rolled-up bytes, from the background scan
        self._files = []            # flat (path, size) from the scan, for search
        self._scan_done = False
        self._scan_started = False
        self._server_ok = False
        self._busy = False
        self._scan_cancel = _CancelToken()

        v = QVBoxLayout(self)
        self.status = QLabel("Opening the volume…")
        v.addWidget(self.status)
        self.busy = QProgressBar()
        self.busy.setRange(0, 0)   # animated while the volume opens and the scan runs
        v.addWidget(self.busy)

        # Search + folder sizes need one full read of the volume, which is heavy on a big disk.
        # Make it opt-in (a button) rather than auto-on-open: the tree browses instantly without
        # it, and nothing competes for the disk unless the user asks for search/sizes.
        srow = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Whole-volume search — run the scan first (button at right)…")
        self.search.setClearButtonEnabled(True)
        self.search.setEnabled(False)
        self.search.textChanged.connect(self._on_search)
        srow.addWidget(self.search, 1)
        self.scan_btn = QPushButton("Scan for sizes && search")
        self.scan_btn.setToolTip(
            "Read the whole volume once to turn on folder sizes and whole-volume search. "
            "Optional — you can browse the tree and extract without it.")
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self._begin_scan)
        srow.addWidget(self.scan_btn)
        v.addLayout(srow)

        # Page 0: the lazy tree.  Page 1: flat search results.
        self.stack = QStackedWidget()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size"])
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setUniformRowHeights(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.itemExpanded.connect(self._on_item_expanded)
        self.tree.itemSelectionChanged.connect(self._update_extract_enabled)
        self.stack.addWidget(self.tree)

        self.model = _FileListModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.doubleClicked.connect(lambda *_: self._extract_selected())
        self.table.selectionModel().selectionChanged.connect(self._update_extract_enabled)
        self.stack.addWidget(self.table)
        v.addWidget(self.stack, 1)

        row = QHBoxLayout()
        self.count_lbl = QLabel("")
        row.addWidget(self.count_lbl)
        row.addStretch(1)
        self.extract_btn = QPushButton("Extract selected…")
        self.extract_btn.setObjectName("primary")
        self.extract_btn.setEnabled(False)
        self.extract_btn.clicked.connect(self._extract_selected)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        row.addWidget(self.extract_btn)
        row.addWidget(close_btn)
        v.addLayout(row)

        self._start_server()

    # ---- dir-server: the lazy tree ----
    def _start_server(self):
        self._dthread = QThread()
        self._dworker = DirServerWorker(self.disk_path)
        self._dworker.moveToThread(self._dthread)
        self._dthread.started.connect(self._dworker.start)
        self._dworker.ready.connect(self._on_server_ready)
        self._dworker.listed.connect(self._on_listed)
        self._dworker.treed.connect(self._on_treed)
        self._want_listdir.connect(self._dworker.do_listdir)
        self._want_listtree.connect(self._dworker.do_listtree)
        self._want_shutdown.connect(self._dworker.shutdown)
        self._dthread.start()

    def _next_req(self, item=None):
        self._req_id += 1
        if item is not None:
            self._pending[self._req_id] = item
        return self._req_id

    def _on_server_ready(self, status, reader, detail):
        if status != "ready":
            self.busy.setVisible(False)
            self.status.setText({
                "no_volume": "No readable NTFS filesystem was found inside this disk.",
                "dead": "The volume browser could not start (the reader process exited).",
            }.get(status, "Could not open the volume: " + (detail or "unknown")))
            return
        self._server_ok = True
        self.busy.setVisible(False)                 # tree is usable now; no scan running yet
        self.scan_btn.setEnabled(True)
        self.status.setText("Expand a folder to browse it. For folder sizes and whole-volume "
                            "search, click “Scan for sizes & search”.")
        self.tree.clear()
        self._dir_items.clear()
        root_req = self._next_req()
        self._pending[root_req] = None          # None target => these go in as top-level items
        self._want_listdir.emit(root_req, "/")

    def _make_item(self, entry):
        it = QTreeWidgetItem()
        it.setText(0, entry["name"])
        it.setData(0, self.PATH_ROLE, entry["path"])
        it.setData(0, self.ISDIR_ROLE, bool(entry["is_dir"]))
        it.setData(0, self.LOADED_ROLE, False)
        if entry["is_dir"]:
            self._dir_items[entry["path"]] = it
            sz = self._sizes.get(entry["path"])
            it.setText(1, human_bytes(sz) if sz is not None else "")
            it.addChild(QTreeWidgetItem(["Loading…", ""]))   # gives the expand arrow
        else:
            it.setText(1, human_bytes(entry.get("size") or 0))
        return it

    def _on_listed(self, req_id, path, entries, error):
        if req_id not in self._pending:
            return
        target = self._pending.pop(req_id)
        if error is not None:
            if target is not None:
                target.takeChildren()
                target.addChild(QTreeWidgetItem([f"(could not read: {error})", ""]))
            else:
                self.status.setText(f"Could not read the volume root: {error}")
            return
        items = [self._make_item(e) for e in entries]
        if target is None:
            self.tree.addTopLevelItems(items)
        else:
            target.takeChildren()           # drop the "Loading…" placeholder
            target.addChildren(items)
        self._update_extract_enabled()

    def _on_item_expanded(self, item):
        if item.data(0, self.ISDIR_ROLE) and not item.data(0, self.LOADED_ROLE):
            item.setData(0, self.LOADED_ROLE, True)
            self._want_listdir.emit(self._next_req(item), item.data(0, self.PATH_ROLE))

    # ---- background scan: folder sizes + whole-volume search (opt-in) ----
    def _begin_scan(self):
        if self._scan_started or not self._server_ok:
            return
        self._scan_started = True
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning…")
        self.busy.setVisible(True)
        self.status.setText("Reading the whole volume for sizes and search…")
        self._start_scan()

    def _start_scan(self):
        self._sthread = QThread()
        self._sworker = VolumeListWorker(self.disk_path, self._scan_cancel)
        self._sworker.moveToThread(self._sthread)
        self._sthread.started.connect(self._sworker.run)
        # Connect to bound methods, never bare lambdas: a lambda has no receiver QObject, so Qt
        # runs it in the EMITTER's (worker) thread and any widget touch there is a cross-thread
        # violation -- which is what hung the window mid-extract.
        self._sworker.progress.connect(self._on_scan_progress)
        self._sworker.finished.connect(self._on_scan_done)
        self._sworker.finished.connect(self._sthread.quit)
        self._sthread.start()

    def _on_scan_progress(self, n):
        self.status.setText(f"Scanning for sizes and search… {n:,} files")

    def _on_scan_done(self, outcome, files, sizes):
        self.busy.setVisible(False)
        if not self._server_ok:
            return                      # a hard open failure already owns the status line
        if outcome.get("status") not in ("completed", "cancelled"):
            self.status.setText("Browsing works; the size/search scan could not finish.")
            self._scan_started = False               # let the user retry
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("Scan for sizes && search")
            return
        self._files = files
        self._scan_done = True
        self.model.set_files(files)
        self._sizes = sizes             # already rolled up on the worker thread
        for dpath, it in self._dir_items.items():        # fill sizes into folders already shown
            sz = self._sizes.get(dpath)
            if sz is not None:
                it.setText(1, human_bytes(sz))
        self.search.setEnabled(True)
        self.search.setPlaceholderText("Search the whole volume by name or path…")
        self.scan_btn.setText("Scanned ✓")
        self.status.setText(
            f"{len(files):,} files scanned. Expand folders, or search the whole volume.")

    def _on_search(self, text):
        if not self._scan_done:
            return
        text = text.strip()
        if text:
            self.model.set_query(text)
            self.stack.setCurrentIndex(1)
            self.count_lbl.setText(f"{self.model.rowCount():,} match(es)")
        else:
            self.stack.setCurrentIndex(0)
            self.count_lbl.setText("")
        self._update_extract_enabled()

    # ---- selection / extract ----
    def _update_extract_enabled(self, *args):
        if self._busy:
            self.extract_btn.setEnabled(False)
            return
        if self.stack.currentIndex() == 1:
            has = bool(self.table.selectionModel().selectedRows())
        else:
            has = bool(self.tree.selectedItems())
        self.extract_btn.setEnabled(has)

    def _selection(self):
        """(file_paths, dir_paths) from whichever view is active."""
        if self.stack.currentIndex() == 1:
            rows = {i.row() for i in self.table.selectionModel().selectedRows()}
            return [self.model.path_at(r) for r in sorted(rows)], []
        files, dirs = [], []
        for it in self.tree.selectedItems():
            p = it.data(0, self.PATH_ROLE)
            if p is None:
                continue
            (dirs if it.data(0, self.ISDIR_ROLE) else files).append(p)
        return files, dirs

    def _extract_selected(self):
        files, dirs = self._selection()
        if not files and not dirs:
            QMessageBox.information(self, "Nothing selected",
                                    "Select one or more files or folders first.")
            return
        dest = QFileDialog.getExistingDirectory(self, "Extract selected to…")
        if not dest:
            return
        self._busy = True
        self._update_extract_enabled()
        self.search.setEnabled(False)
        self.busy.setRange(0, 0)
        self.busy.setVisible(True)
        self._extract_files = list(files)
        self._extract_dirs = list(dirs)
        self._extract_dest = dest
        if self._extract_dirs:
            self.status.setText("Enumerating selected folder(s)…")
            self._drain_dirs()
        else:
            self._launch_extract()

    def _drain_dirs(self):
        if self._extract_dirs:
            self._tree_req = self._next_req()
            self._want_listtree.emit(self._tree_req, self._extract_dirs.pop(0))
        else:
            self._launch_extract()

    def _on_treed(self, req_id, path, files, truncated, error):
        if getattr(self, "_tree_req", None) != req_id:
            return
        if error is not None:
            self._finish_busy()
            self.status.setText(f"Could not enumerate {path}: {error}")
            QMessageBox.warning(self, "Folder could not be read", f"{path}\n\n{error}")
            return
        if truncated:
            self.status.setText(f"{path} is very large; extracting the first part…")
        self._extract_files.extend(p for p, _s in files)
        self._drain_dirs()

    def _launch_extract(self):
        paths = list(dict.fromkeys(self._extract_files))   # de-dup, preserve order
        if not paths:
            self._finish_busy()
            self.status.setText("Nothing to extract in the selection.")
            return
        self.status.setText(f"Extracting {len(paths):,} file(s)…")
        self._ecancel = _CancelToken()
        self._ethread = QThread()
        self._eworker = NtfsExtractWorker(self.disk_path, None, self._extract_dest, 0,
                                          self._ecancel, only_paths=paths)
        self._eworker.moveToThread(self._ethread)
        self._ethread.started.connect(self._eworker.run)
        # Bound methods only (see _start_scan): a lambda slot would run _on_extracted -- which
        # opens a modal QMessageBox -- on the worker thread, spinning an event loop on the wrong
        # thread and freezing the UI. Bound methods of this dialog are queued to the UI thread.
        self._eworker.progress.connect(self._on_extract_progress)
        self._eworker.finished.connect(self._on_extract_finished)
        self._eworker.failed.connect(self._on_extract_failed)
        self._eworker.finished.connect(self._ethread.quit)
        self._eworker.failed.connect(self._ethread.quit)
        self._ethread.start()

    def _on_extract_progress(self, frac, label):
        self.status.setText(label)

    def _on_extract_finished(self, outcome):
        self._on_extracted(outcome, self._extract_dest)

    def _finish_busy(self):
        self.busy.setVisible(False)
        self._busy = False
        if self._scan_done:
            self.search.setEnabled(True)
        self._update_extract_enabled()

    def _on_extracted(self, outcome, dest):
        self._finish_busy()
        if outcome is None:
            self.status.setText("Extraction cancelled.")
            return
        ok = outcome.get("files_recovered", 0)
        total = outcome.get("bytes_written", 0)
        self.status.setText(f"Recovered {ok:,} file(s), {human_bytes(total)} to {dest}")
        box = QMessageBox(self)
        box.setWindowTitle("Extraction complete")
        box.setText(f"Recovered {ok:,} file(s) ({human_bytes(total)}) to:\n{dest}")
        open_btn = box.addButton("Open folder", QMessageBox.AcceptRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is open_btn:
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QDesktopServices
            QDesktopServices.openUrl(QUrl.fromLocalFile(dest))

    def _on_extract_failed(self, message):
        self._finish_busy()
        self.status.setText("Extraction failed.")
        QMessageBox.warning(self, "Extraction failed", message)

    def reject(self):
        self._scan_cancel.cancel()
        if hasattr(self, "_ecancel"):
            self._ecancel.cancel()
        try:
            self._want_shutdown.emit()      # close the persistent reader child
        except Exception:  # noqa: BLE001
            pass
        for attr in ("_dthread", "_sthread", "_ethread"):
            th = getattr(self, attr, None)
            if th is not None:
                th.quit()
                th.wait(3000)
        super().reject()


class CarveWorker(QObject):
    """Run PhotoRec against the recoverable region, off the UI thread."""
    progress = Signal(float, str)
    finished = Signal(object)   # summary dict, or None if cancelled
    failed = Signal(str)

    def __init__(self, path, report, out_dir, cancel_token):
        super().__init__()
        self.path = path
        self.report = report
        self.out_dir = out_dir
        self.cancel_token = cancel_token

    def run(self):
        try:
            from . import carve
            summary = carve.carve_recoverable(
                self.path, self.report, self.out_dir,
                progress=lambda f, label: self.progress.emit(f, label),
                log=lambda line: self.progress.emit(0.5, line[:80]),
                cancel_check=self.cancel_token,
            )
            self.finished.emit(None if self.cancel_token() else summary)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class HashAndReportWorker(QObject):
    """Optionally hash the input, then write the HTML report -- off the UI thread so a
    slow hash on a large disk doesn't freeze the window or block cancellation."""
    progress = Signal(float, str)
    finished = Signal(str)   # out_path, or "" if cancelled
    failed = Signal(str)

    def __init__(self, path, report, out_path, do_hash, cancel_token):
        super().__init__()
        self.path = path
        self.report = report
        self.out_path = out_path
        self.do_hash = do_hash
        self.cancel_token = cancel_token

    def run(self):
        try:
            from . import report as report_mod
            sha = None
            if self.do_hash:
                try:
                    sha = report_mod.sha256_of_input(
                        self.path,
                        progress=lambda f, label: self.progress.emit(f, label),
                        cancel_check=self.cancel_token)
                except KeyboardInterrupt:
                    self.finished.emit("")
                    return
            report_mod.write_html_report(
                self.path, self.report, self.out_path, sha256=sha,
                contact=report_mod.contact_from_env(),
                scan_params={"scan mode": self.report.mode,
                             "block size": self.report.block_size,
                             "pattern": self.report.pattern})
            self.finished.emit(self.out_path)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


def _is_admin() -> bool:
    r"""True when running elevated on Windows. Raw \\.\ device opens need this."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def human_bytes(n: int) -> str:
    """Byte count in the user's locale (separators, decimal mark, unit names).

    DataSizeTraditionalFormat keeps the familiar KB/MB/GB labels with 1024 steps,
    matching how Windows itself reports file sizes."""
    from PySide6.QtCore import QLocale
    return QLocale.system().formattedDataSize(int(n), 1, QLocale.DataSizeTraditionalFormat)


def human_count(n: int) -> str:
    """Integer with the locale's own thousands separators."""
    from PySide6.QtCore import QLocale
    return QLocale.system().toString(int(n))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        from PySide6.QtCore import QSettings
        self._settings = QSettings("IronSights", "ScanCrypt")   # needed by the menus
        self.setWindowTitle(f"ScanCrypt v{__version__}")
        self._build_menus()
        self.resize(760, 560)

        self.path: str | None = None
        self.report: engine.ScanReport | None = None
        self.batch_result = None
        self.thread: QThread | None = None
        self.worker: QObject | None = None
        self.cancel_token: _CancelToken | None = None

        root = QWidget()
        layout = QVBoxLayout(root)

        file_row = QHBoxLayout()
        self.setAcceptDrops(True)
        self.path_label = QLabel("No file selected. You can drag one onto this window.")
        self.path_label.setStyleSheet("color: #3A4150;")
        browse_btn = QPushButton("Choose file / disk image…")
        browse_btn.clicked.connect(self.choose_file)
        folder_btn = QPushButton("Scan a folder…")
        folder_btn.setToolTip(
            "Scan every file under a folder (a share, a backup directory) and roll the "
            "results up into one incident-wide recoverable figure with a per-file list.")
        folder_btn.clicked.connect(self.choose_folder)
        device_btn = QPushButton("Raw device…")
        device_btn.setToolTip(
            "Scan a raw Windows block device in place, e.g. \\\\.\\PhysicalDrive1 or "
            "\\\\.\\D: -- requires running as Administrator. Read-only."
        )
        device_btn.clicked.connect(self.choose_device)
        if sys.platform != "win32":
            device_btn.setEnabled(False)
            device_btn.setToolTip("Raw device scanning is only available on Windows.")
        elif not _is_admin():
            device_btn.setText("Raw device… (needs Admin)")
        file_row.addWidget(browse_btn)
        file_row.addWidget(folder_btn)
        file_row.addWidget(device_btn)
        file_row.addWidget(self.path_label, stretch=1)
        layout.addLayout(file_row)

        if sys.platform == "win32" and not _is_admin():
            elev = QLabel(
                "Running without Administrator rights: files and disk images scan fine, "
                "but scanning a raw drive (\\\\.\\C:) needs an elevated launch. "
                "Right-click the exe and choose \"Run as administrator\" if you need that.")
            elev.setWordWrap(True)
            elev.setStyleSheet("color:#8a6d1a;background:#fdf6dd;border:1px solid #e8d48a;"
                               "border-radius:3px;padding:6px 10px;")
            layout.addWidget(elev)

        mode_box = QGroupBox("Scan mode")
        mode_row = QHBoxLayout(mode_box)
        self.adaptive_radio = QRadioButton("Adaptive (recommended -- boundary search, escalates to full scan if needed)")
        self.full_radio = QRadioButton("Force full block-by-block scan (slower, catches scattered/periodic encryption)")
        self.adaptive_radio.setChecked(True)
        mode_row.addWidget(self.adaptive_radio)
        mode_row.addWidget(self.full_radio)
        layout.addWidget(mode_box)

        action_row = QHBoxLayout()
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self.start_scan)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_running_job)
        # One-click move to the next file: victims rarely triage just one.
        self.another_btn = QPushButton("Scan another file…")
        self.another_btn.setVisible(False)
        self.another_btn.clicked.connect(self.choose_file)
        action_row.addWidget(self.scan_btn)
        action_row.addWidget(self.cancel_btn)
        action_row.addWidget(self.another_btn)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_label = QLabel("")
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_label)

        report_box = QGroupBox("Report")
        report_layout = QVBoxLayout(report_box)
        self.verdict_label = QLabel("Run a scan to see recoverability.")
        self.verdict_label.setWordWrap(True)
        f = self.verdict_label.font()
        f.setPointSize(f.pointSize() + 2)
        f.setBold(True)
        self.verdict_label.setFont(f)
        report_layout.addWidget(self.verdict_label)

        self.entropy_strip = EntropyStripWidget()
        report_layout.addWidget(self.entropy_strip)
        self.legend_label = QLabel(
            '<span style="color:#FF5A5A">■</span> encrypted&nbsp;&nbsp;'
            '<span style="color:#37E28C">■</span> intact / recoverable&nbsp;&nbsp;'
            '<span style="color:#2a3242">■</span> empty (unallocated)'
        )
        self.legend_label.setStyleSheet("color:#3A4150; font-size: 12px;")
        report_layout.addWidget(self.legend_label)

        # Plain-language guidance for people who are not incident responders: after a
        # scan this says, in words, what the best next action is and how to do it.
        self.next_steps = QLabel()
        self.next_steps.setWordWrap(True)
        self.next_steps.setTextFormat(Qt.RichText)
        self.next_steps.setOpenExternalLinks(True)
        self.next_steps.setVisible(False)
        report_layout.addWidget(self.next_steps)

        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMaximumHeight(220)
        report_layout.addWidget(self.detail_text)
        layout.addWidget(report_box, stretch=1)

        extract_row = QHBoxLayout()
        self.extract_btn = QPushButton("Extract recoverable data…")
        self.extract_btn.setEnabled(False)
        self.extract_btn.clicked.connect(self.start_extract)
        self.report_btn = QPushButton("Save HTML report…")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self.save_report)
        self.browse_btn = QPushButton("Browse files…")
        self.browse_btn.setToolTip("Browse the volume as a folder tree (opens instantly, reads "
                                   "each folder as you expand it), search the whole volume by "
                                   "name, and extract just the files or folders you pick.")
        self.browse_btn.setEnabled(False)
        self.browse_btn.clicked.connect(self.open_volume_browser)
        self.ntfs_btn = QPushButton("Extract files from volume…")
        self.ntfs_btn.setToolTip("Copy files out of an intact NTFS volume found in the "
                                 "recoverable region (structure-aware, read-only).")
        self.ntfs_btn.setEnabled(False)
        self.ntfs_btn.clicked.connect(self.start_ntfs_extract)
        self.carve_btn = QPushButton("Carve loose files…")
        self.carve_btn.setToolTip("Run PhotoRec over the recoverable region to carve out "
                                  "loose files by signature. Requires PhotoRec installed.")
        self.carve_btn.setEnabled(False)
        self.carve_btn.clicked.connect(self.start_carve)
        self.contribute_btn = QPushButton("Help improve ScanCrypt…")
        self.contribute_btn.setToolTip("Generate a privacy-safe family fingerprint for this "
                                       "file (no file contents) to help ScanCrypt recognise "
                                       "the strain, with a ready-to-submit form.")
        self.contribute_btn.setEnabled(False)
        self.contribute_btn.clicked.connect(self.open_contribute)
        extract_row.addWidget(self.extract_btn)
        extract_row.addWidget(self.report_btn)
        extract_row.addWidget(self.browse_btn)
        extract_row.addWidget(self.ntfs_btn)
        extract_row.addWidget(self.carve_btn)
        extract_row.addWidget(self.contribute_btn)
        extract_row.addStretch(1)
        layout.addLayout(extract_row)

        caveat = QLabel(
            "This recovers the byte-range that was never encrypted -- it does not "
            "decrypt anything. Always report recoverability as \"most, not all,\" "
            "never a guarantee. Small files are usually fully encrypted."
        )
        caveat.setWordWrap(True)
        caveat.setStyleSheet("color: #4A5160; font-style: italic;")
        layout.addWidget(caveat)

        self.setCentralWidget(root)

        # Restore the previous session's window size/position (QSettings).
        geo = self._settings.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)

    def closeEvent(self, event):
        self._settings.setValue("geometry", self.saveGeometry())
        super().closeEvent(event)

    # ---------------------------------------------------------------- file selection

    def _last_dir(self) -> str:
        return str(self._settings.value("last_dir", ""))

    def _remember_dir(self, path: str):
        d = str(Path(path).parent) if Path(path).is_file() else str(path)
        self._settings.setValue("last_dir", d)

    def _build_menus(self):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QAction, QDesktopServices

        def link(menu, text, url):
            act = QAction(text, self)
            act.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(url)))
            menu.addAction(act)

        def item(menu, text, slot, shortcut=None):
            act = QAction(text, self)
            if shortcut:
                act.setShortcut(shortcut)
            act.triggered.connect(slot)
            menu.addAction(act)

        m_file = self.menuBar().addMenu("&File")
        item(m_file, "&Open file or disk image…", self.choose_file, "Ctrl+O")
        item(m_file, "Scan raw &device…", self.choose_device)
        m_file.addSeparator()
        item(m_file, "Save HTML &report…", self.save_report, "Ctrl+S")
        m_file.addSeparator()
        item(m_file, "E&xit", self.close, "Ctrl+Q")

        m_help = self.menuBar().addMenu("&Help")
        link(m_help, "ScanCrypt website", "https://scancrypt.org")
        link(m_help, "Hit by ransomware? Start here",
             "https://scancrypt.org/recover.html")
        link(m_help, "Report an issue",
             "https://github.com/ironsightscyber/scancrypt/issues")
        m_help.addSeparator()
        # Troubleshooting mode: verbose diagnostic log for the next recovery. Persisted so it
        # survives the crash the user is trying to capture.
        self.debug_action = QAction("&Troubleshooting mode (verbose log)", self)
        self.debug_action.setCheckable(True)
        self.debug_action.setChecked(self._settings.value("debug_mode", False, type=bool))
        self.debug_action.toggled.connect(
            lambda on: self._settings.setValue("debug_mode", on))
        m_help.addAction(self.debug_action)
        m_help.addSeparator()
        item(m_help, "&License", self._show_license)
        item(m_help, "&About ScanCrypt", self._show_about)

    def _show_license(self):
        QMessageBox.information(
            self, "License",
            "ScanCrypt is free and open-source software, released under the "
            "Apache License, Version 2.0.\n\n"
            "You may use, copy, modify, and redistribute it, including commercially, "
            "under the terms of that license. It is provided \"AS IS\", without "
            "warranties or conditions of any kind; the authors accept no liability "
            "for its use. The full text ships with the source distribution and at:\n\n"
            "https://www.apache.org/licenses/LICENSE-2.0\n\n"
            "Copyright 2026 IronSights Pty Ltd.")

    def _show_about(self):
        from . import __version__
        QMessageBox.about(
            self, "About ScanCrypt",
            f"<h3>ScanCrypt v{__version__}</h3>"
            "<p>Finds and extracts the parts of a ransomware-encrypted file that "
            "were never actually encrypted. Read-only: it never modifies what it scans.</p>"
            "<p>A free, open-source tool created and maintained by "
            "<a href='https://ironsights.com.au'>IronSights</a>, an Australian cyber "
            "security company.</p>"
            "<p><a href='https://scancrypt.org'>scancrypt.org</a> · "
            "<a href='https://github.com/ironsightscyber/scancrypt'>source on GitHub</a></p>"
            "<p style='color:#888'>Apache License 2.0. No warranty. It is not a "
            "decryptor and cannot recover fully-encrypted data.</p>")

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose file or disk image",
                                              self._last_dir())
        if not path:
            return
        self._remember_dir(path)
        self._set_input(path)

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose a folder to scan",
                                                self._last_dir())
        if not path:
            return
        self._remember_dir(path)
        self._set_input(path)
        self.path_label.setText(f"{path}  (folder: every file underneath will be scanned)")

    # Drag a file anywhere onto the window to select it.
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and event.mimeData().urls()[0].isLocalFile():
            event.acceptProposedAction()

    def dropEvent(self, event):
        path = event.mimeData().urls()[0].toLocalFile()
        if not path:
            return
        if Path(path).is_file():
            self._remember_dir(path)
            self._set_input(path)
        elif Path(path).is_dir():
            self._remember_dir(path)
            self._set_input(path)
            self.path_label.setText(
                f"{path}  (folder: every file underneath will be scanned)")

    def choose_device(self):
        if not _is_admin():
            QMessageBox.warning(
                self, "Administrator rights needed",
                "Windows only lets elevated processes open raw devices, so this scan "
                "would fail with access denied.\n\n"
                "Close ScanCrypt, right-click scancrypt-gui.exe and choose "
                "\"Run as administrator\", then try again.\n\n"
                "Scanning ordinary files and disk images does not need elevation.")
            return
        path, ok = QInputDialog.getText(
            self, "Scan raw device",
            "Device path (read-only; requires Administrator):",
            text="\\\\.\\PhysicalDrive1",
        )
        if not ok or not path:
            return
        if not engine.is_scannable(path):
            QMessageBox.warning(
                self, "Not a valid device path",
                "Enter a raw Windows device path like \\\\.\\PhysicalDrive1 or \\\\.\\D:",
            )
            return
        self._set_input(path)

    def _set_input(self, path: str):
        self.path = path
        self.path_label.setText(path)
        self.path_label.setStyleSheet("color: #000;")
        self.scan_btn.setEnabled(True)
        self.extract_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        self.ntfs_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.carve_btn.setEnabled(False)
        self.contribute_btn.setEnabled(False)
        self.report = None
        self.batch_result = None
        self.verdict_label.setText("Run a scan to see recoverability.")
        self.detail_text.setPlainText("")
        self.entropy_strip.clear()
        self.next_steps.setVisible(False)
        self.another_btn.setVisible(False)

    # ---------------------------------------------------------------- scan lifecycle

    def start_scan(self):
        if not self.path:
            return
        self._set_busy(True)
        self.cancel_token = _CancelToken()
        self.thread = QThread()
        if Path(self.path).is_dir():
            self.worker = BatchWorker(self.path, self.full_radio.isChecked(),
                                      self.cancel_token)
            self.worker.finished.connect(self._on_batch_finished)
        else:
            self.worker = ScanWorker(self.path, self.full_radio.isChecked(),
                                     self.cancel_token)
            self.worker.finished.connect(self._on_scan_finished)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.start()

    def _on_batch_finished(self, result):
        self._set_busy(False)
        if result is None:
            self.progress_label.setText("Cancelled.")
            return
        self.batch_result = result
        self.report = None
        self.entropy_strip.clear()
        self.progress_label.setText("")
        self.another_btn.setVisible(True)
        self.report_btn.setEnabled(True)

        pct = result.recoverable_pct
        self.verdict_label.setText(
            f"{pct:.2f}% of this folder is recoverable "
            f"({human_bytes(result.recoverable_bytes)} of {human_bytes(result.total_bytes)}) "
            f"across {human_count(result.scanned)} scanned files.")
        self.verdict_label.setStyleSheet(
            "color: " + ("#2e7d32" if pct >= 60 else "#e65100" if pct >= 20 else "#c62828"))

        lines = []
        strain = result.identified_strain()
        if strain:
            lines.append(f"Ransomware strain: {strain} "
                         f"({len(result.notes)} ransom note(s) found)")
        lines.append(f"Files scanned: {human_count(result.scanned)}, "
                     f"skipped: {human_count(result.skipped)}, "
                     f"errors: {human_count(result.errors)}")
        top = sorted(result.files, key=lambda f: -f.recoverable_bytes)[:10]
        if top:
            lines.append("")
            lines.append("Biggest recovery wins (scan these individually to extract):")
            for f in top:
                if f.recoverable_bytes <= 0:
                    break
                lines.append(f"  • {f.path}  ({human_bytes(f.recoverable_bytes)} recoverable)")
        self.detail_text.setPlainText("\n".join(lines))
        self._update_next_steps_batch(result)

    def _update_next_steps_batch(self, result):
        text = (f"<b>Next step:</b> click <b>Save HTML report</b> to get the incident "
                f"report: the overall figure plus every file ranked by how much comes "
                f"back. Share it with management, your insurer, or a responder. To "
                f"actually recover data, scan the biggest important files individually "
                f"(the list above names them) and use Extract from there.")
        self.next_steps.setText(text)
        self.next_steps.setStyleSheet(
            "QLabel{background:#eef2f7;border:1px solid #ccd5e0;border-radius:4px;"
            "padding:10px 12px;color:#222;}")
        self.next_steps.setVisible(True)

    def _on_scan_finished(self, report):
        self._set_busy(False)
        if report is None:
            self.progress_label.setText("Cancelled.")
            return
        self.report = report
        self._render_report(report)
        self.extract_btn.setEnabled(report.pattern != "fully-encrypted")
        self.report_btn.setEnabled(True)
        self.ntfs_btn.setEnabled(self._can_extract_volume(report))
        self.browse_btn.setEnabled(self._can_extract_volume(report))
        self.carve_btn.setEnabled(self._can_carve(report))
        self.contribute_btn.setEnabled(True)   # any scanned file can seed a family fingerprint
        self._explain_disabled_actions(report)
        self._update_next_steps(report)
        self.another_btn.setVisible(True)

    _IMAGE_EXTS = {".vhd", ".vhdx", ".vmdk", ".img", ".raw", ".dd", ".e01", ".001", ".iso"}
    # Container formats Windows can mount natively, so the easy path is extract + mount,
    # not ScanCrypt's raw volume extraction (which cannot parse the container wrapper).
    _MOUNTABLE_EXTS = {".vhd", ".vhdx", ".vmdk"}

    def _real_ext(self) -> str:
        """The victim file's own extension, ignoring the extension the ransomware appended
        (invoices.vhdx.[id].ndm448 -> .vhdx)."""
        if not self.path:
            return ""
        parts = Path(self.path).name.lower().split(".")
        for part in reversed(parts):
            ext = "." + part
            if ext in self._IMAGE_EXTS:
                return ext
        return Path(self.path).suffix.lower()

    def _looks_like_disk_image(self):
        if not self.path:
            return False
        if engine.is_scannable(self.path) and not Path(self.path).is_file():
            return True   # raw device
        return self._real_ext() in self._IMAGE_EXTS

    def _update_next_steps(self, report):
        """One plain-language paragraph: what to click next, based on what the scan found."""
        style = ("QLabel{{background:{bg};border:1px solid {bd};border-radius:4px;"
                 "padding:10px 12px;color:#222;}}")
        if report.pattern == "fully-encrypted":
            text = ("<b>Nothing recoverable was found in this file.</b> Small files are "
                    "usually encrypted end to end. Try your largest, most important files "
                    "instead (databases, virtual machine disks, backup archives), and check "
                    "<a href='https://www.nomoreransom.org'>nomoreransom.org</a> for a free "
                    "decryptor for this strain.")
            bg, bd = "#fdecec", "#f0b6b6"
        elif self._real_ext() in self._MOUNTABLE_EXTS and self._is_container():
            ext = self._real_ext()
            text = (f"<b>This is a virtual disk ({ext}). ScanCrypt can read the files "
                    "straight out of it, even if it won't mount.</b><br>"
                    "<b>Best next step:</b> click <b>Extract files from volume…</b> and "
                    "choose an empty destination folder. ScanCrypt opens the disk, finds "
                    "the Windows filesystem inside (handling dynamically-expanding disks "
                    "whose data is scattered through the file), and copies your files out "
                    "with their names and folders. Files sitting in encrypted regions may "
                    "come out damaged; the rest recover cleanly.<br><br>"
                    "Alternative: <b>Extract recoverable data</b> saves a rebuilt "
                    f"<b>{ext}</b> you can try to Attach VHD (read-only) in Windows Disk "
                    "Management, but that only works if the disk's header survived.")
            bg, bd = "#eaf7ef", "#b9e4c8"
        elif self._real_ext() in self._MOUNTABLE_EXTS:
            ext = self._real_ext()
            text = (f"<b>This is a virtual disk ({ext}).</b> Reading files straight out of "
                    "it needs the dissect.hypervisor package (bundled in the Windows build). "
                    "Otherwise: click <b>Extract recoverable data</b>, save it with a "
                    f"<b>{ext}</b> name, then Attach VHD (read-only) in Windows Disk "
                    "Management, if the disk's header survived the encryption.")
            bg, bd = "#eaf7ef", "#b9e4c8"
        elif self._ntfs_offset(report) is not None:
            text = ("<b>Good news: an intact Windows filesystem (NTFS) was found inside "
                    "this image.</b> Your files can likely be copied out with their names "
                    "and folders. <b>Best next step:</b> click <b>Extract files from "
                    "volume…</b> below and choose an empty destination folder. "
                    "Alternative: <b>Extract recoverable data</b> can save the volume as a "
                    "partition image, which <a href='https://www.7-zip.org'>7-Zip</a> "
                    "(right-click → Open archive) and free forensic tools like "
                    "<a href='https://www.exterro.com/digital-forensics-software/ftk-imager'>"
                    "FTK Imager</a> open for browsing.")
            bg, bd = "#eaf7ef", "#b9e4c8"
        elif self._looks_like_disk_image():
            text = ("<b>No intact filesystem was detected in the readable part of this "
                    "image</b>, so files cannot be copied out with their names here. You "
                    "can still: <b>Extract recoverable data</b> to save the readable bytes, "
                    "<b>Carve loose files</b> to recover file contents without names "
                    "(needs PhotoRec), or open the original image in a free forensic tool "
                    "like <a href='https://www.exterro.com/digital-forensics-software/"
                    "ftk-imager'>FTK Imager</a> to inspect it by hand.")
            bg, bd = "#eef2f7", "#ccd5e0"
        else:
            text = ("<b>Next step:</b> click <b>Extract recoverable data</b> to save the "
                    "readable part of this file, then rename the result back to its real "
                    "name and type (drop the .recovered ending and the extension the "
                    "ransomware added). Files with a damaged start may need repair; a "
                    "database, for example, usually needs a rebuild before it opens.")
            bg, bd = "#eef2f7", "#ccd5e0"
        self.next_steps.setText(text)
        self.next_steps.setStyleSheet(style.format(bg=bg, bd=bd))
        self.next_steps.setVisible(True)

    def _explain_disabled_actions(self, report):
        """Disabled buttons should say why, or they read as broken."""
        if self._is_container():
            self.ntfs_btn.setToolTip(
                "Open this virtual disk, find the Windows filesystem inside it, and copy "
                "files out with their names and folders. Handles dynamically-expanding "
                "disks that will not mount because the container header was encrypted.")
        elif self._ntfs_offset(report) is None:
            self.ntfs_btn.setToolTip(
                "No NTFS volume was detected in this scan. This applies to disk images "
                "and raw drives, not single files: when the volume inside survived, its "
                "files can be copied out with names and folders intact.")
        else:
            self.ntfs_btn.setToolTip("Copy files out of the intact NTFS volume found in "
                                     "the scanned image, with names and folders intact.")
        if not self._can_carve(report):
            from . import carve
            self.carve_btn.setToolTip(
                "Carving is unavailable: PhotoRec was not found on this machine."
                if report and report.pattern != "fully-encrypted" and not carve.available()
                else "Nothing to carve: the file reads as fully encrypted.")

    @staticmethod
    def _can_carve(report):
        if not report or report.pattern == "fully-encrypted":
            return False
        from . import carve
        return carve.available()

    def _is_container(self) -> bool:
        """The input is a virtual-disk container we can read through (VHDX/VHD/VMDK)."""
        if not self.path:
            return False
        from . import ntfs
        return ntfs.container_ext(self.path) is not None and ntfs.container_available()

    def _can_extract_volume(self, report) -> bool:
        """Volume extraction is possible when a raw NTFS offset was detected, or the input
        is a virtual-disk container we can open and search for the filesystem inside."""
        return self._ntfs_offset(report) is not None or self._is_container()

    @staticmethod
    def _ntfs_offset(report):
        """Byte offset of a detected NTFS volume in the report, or None."""
        if not report:
            return None
        for f in report.formats:
            if "NTFS" in f["name"]:
                return f["offset"]
        return None

    def _render_report(self, report: engine.ScanReport):
        color = PATTERN_COLORS.get(report.pattern, "#333")
        self.entropy_strip.set_report(report)
        marker = report_mod.expected_boundary_fraction(report)
        base_legend = (
            '<span style="color:#FF5A5A">■</span> encrypted&nbsp;&nbsp;'
            '<span style="color:#37E28C">■</span> intact / recoverable&nbsp;&nbsp;'
            '<span style="color:#2a3242">■</span> empty (unallocated)'
        )
        if marker is not None:
            base_legend += (
                f'&nbsp;&nbsp;<span style="color:#C3CAD6">┊</span> intended extent '
                f'(~{marker*100:.0f}%)'
            )
        self.legend_label.setText(base_legend)
        self.verdict_label.setText(
            f"{report.recoverable_pct:.2f}% of this file is recoverable "
            f"({human_bytes(report.recoverable_bytes)} of {human_bytes(report.size)}). "
            f"Pattern: {report.pattern}."
        )
        self.verdict_label.setStyleSheet(f"color: {color};")

        lines = [
            f"Scan mode: {report.mode}",
            f"File size: {human_bytes(report.size)} ({report.size:,} bytes)",
            f"Pattern classification: {report.pattern}",
            f"Encrypted bytes: {human_bytes(report.encrypted_bytes)} ({report.encrypted_pct:.4f}%)",
        ]
        if report.family:
            prov = report.family.get("provenance")
            conf = "confirmed" if prov == "validated" else "likely (from public reporting)"
            lines.insert(0, f"Ransomware family: {report.family['family']} — {conf} "
                            f"(matched on {', '.join(report.family['matched_on'])})")
        if report.boundary_offset is not None:
            lines.append(f"Boundary offset: {report.boundary_offset:,} bytes")
        if report.total_blocks is not None:
            lines.append(f"Block size: {report.block_size:,} bytes, {report.total_blocks:,} total blocks")
            lines.append(f"High-entropy blocks: {report.high_entropy_blocks:,}, runs: {report.runs}")
        if report.formats:
            lines.append("")
            lines.append("Detected in recoverable region:")
            for fmt in report.formats:
                lines.append(f"  • {fmt['name']} at offset {fmt['offset']:,} ({fmt['where']})")
                lines.append(f"      → {fmt['extraction_hint']}")
        lines.append("")
        lines.append(report.note)
        self.detail_text.setPlainText("\n".join(lines))

    # ---------------------------------------------------------------- extraction lifecycle

    def start_extract(self):
        if not self.path or not self.report:
            return
        # A scanned disk image with an intact NTFS volume inside: offer to cut the volume
        # out as a standalone partition image, which 7-Zip and forensic tools open
        # directly, instead of a raw byte blob that starts at an arbitrary offset.
        vol_start = vol_len = None
        ntfs_off = self._ntfs_offset(self.report)
        if ntfs_off is not None:
            box = QMessageBox(self)
            box.setWindowTitle("What should the output be?")
            box.setText(
                "The scan found an intact NTFS volume inside this image.\n\n"
                "NTFS volume image (recommended): the volume cut out as a standalone "
                "partition image. Open it in 7-Zip (right-click, Open archive) to browse "
                "and pull files out with names and folders, or load it in forensic "
                "tools.\n\n"
                "Raw readable bytes: every readable byte from the encryption boundary "
                "on, as one blob. For manual carving and analysis.")
            vol_btn = box.addButton("NTFS volume image", QMessageBox.AcceptRole)
            box.addButton("Raw readable bytes", QMessageBox.ActionRole)
            cancel_btn = box.addButton(QMessageBox.Cancel)
            box.setDefaultButton(vol_btn)
            box.exec()
            if box.clickedButton() is cancel_btn:
                return
            if box.clickedButton() is vol_btn:
                vol_start = ntfs_off
                vol_len = engine.ntfs_volume_length(self.path, ntfs_off)

        stem = Path(self.path).name.replace(":", "").replace("\\", "") or "scan"
        mount_ext = self._real_ext() if self._real_ext() in self._MOUNTABLE_EXTS else None
        if vol_start is not None:
            suggested = stem + ".ntfs.img"
        elif mount_ext is not None:
            # virtual disk: suggest a mountable name so Windows can attach it directly,
            # stripping the ransomware's appended extension.
            base = Path(self.path).name
            cut = base.lower().rfind(mount_ext)
            suggested = (base[:cut] + mount_ext) if cut >= 0 else (stem + mount_ext)
        elif engine.is_scannable(self.path) and not Path(self.path).is_file():
            # raw device input: suggest a plain filename, not a path in the device namespace
            suggested = stem + ".recovered"
        else:
            suggested = str(Path(self.path).with_suffix(Path(self.path).suffix + ".recovered"))
        if not Path(suggested).is_absolute():
            import os
            suggested = os.path.join(self._last_dir(), suggested)
        out_path, _ = QFileDialog.getSaveFileName(self, "Save recovered data as…", suggested)
        if not out_path:
            return
        self._remember_dir(out_path)
        self._set_busy(True)
        self.cancel_token = _CancelToken()
        self.thread = QThread()
        self.worker = ExtractWorker(self.path, self.report, out_path, self.cancel_token,
                                    volume_start=vol_start, volume_length=vol_len)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(
            lambda n: self._on_extract_finished(n, out_path, vol_start is not None))
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.start()

    def _on_extract_finished(self, written: int, out_path: str, is_volume: bool = False):
        self._set_busy(False)
        if written < 0:
            self.progress_label.setText("Cancelled.")
            return
        self.progress_label.setText(f"Wrote {human_bytes(written)} to {out_path}")
        if is_volume:
            advice = (
                "This is a standalone NTFS partition image. To browse it, right-click it "
                "in Explorer and choose 7-Zip → Open archive, then copy files out with "
                "their names and folders. Forensic tools (FTK Imager, Autopsy) open it "
                "too. The original was not modified.")
        elif Path(out_path).suffix.lower() in self._MOUNTABLE_EXTS:
            advice = (
                "This is a rebuilt virtual disk. In Windows, open Disk Management → "
                "Action → Attach VHD, pick this file, tick Read-only, and it mounts as a "
                "drive you can browse and copy from. If Windows refuses to mount it, the "
                "disk's header was in the encrypted region. The original was not modified.")
        else:
            advice = (
                "This is a new file holding the readable part of the original; the "
                "original was not modified. To try opening it, rename it back to its "
                "real name and type, dropping the .recovered ending and any extension "
                "the ransomware added (invoices.xlsx.ndm448.recovered → invoices.xlsx). "
                "Files with a damaged start may still need repair, e.g. a database rebuild.")
        box = QMessageBox(self)
        box.setWindowTitle("Extraction complete")
        box.setText(f"Recovered {human_bytes(written)} to:\n{out_path}\n\n{advice}")
        open_btn = box.addButton("Open containing folder", QMessageBox.AcceptRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is open_btn:
            self._open_path(str(Path(out_path).parent))

    # ---------------------------------------------------------------- report

    def open_contribute(self):
        """Build a privacy-safe family fingerprint for the scanned file and show a dialog with a
        ready-to-paste signatures.yaml block plus a button to open the pre-filled issue form.
        Reuses the current scan report, so no re-scan and no file contents are read."""
        if not self.path:
            return
        from . import fingerprint
        try:
            fp = fingerprint.build(self.path, scan_report=self.report)
        except Exception as exc:  # noqa: BLE001 -- advisory feature, never crash the app
            QMessageBox.warning(self, "Fingerprint failed", str(exc))
            return
        stub = fingerprint.to_yaml_stub(fp)
        url = fingerprint.issue_url(fp)

        dlg = QDialog(self)
        dlg.setWindowTitle("Help improve ScanCrypt")
        dlg.setMinimumWidth(660)
        v = QVBoxLayout(dlg)
        if fp.known_family:
            head = (f"Detected family: <b>{fp.known_family}</b> — already recognised by "
                    "ScanCrypt. If this looks like a <i>new variant</i> (different extension or "
                    "note), the block below still helps; otherwise there's nothing to submit.")
        else:
            head = ("This looks like a strain ScanCrypt doesn't name yet. Submitting the block "
                    "below helps it recognise this family for the next victim.")
        note_bit = " and the nearby ransom note" if fp.note_filename else ""
        intro = QLabel(
            "A <b>privacy-safe</b> fingerprint — the extension, a few trailing bytes, the "
            f"encryption pattern{note_bit}. <b>No file contents are read or shared.</b><br><br>"
            + head)
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        v.addWidget(intro)

        box = QPlainTextEdit(stub)
        box.setReadOnly(True)
        box.setStyleSheet("font-family: Menlo, Consolas, monospace; font-size: 12px;")
        v.addWidget(box)

        row = QHBoxLayout()
        copy_btn = QPushButton("Copy signature block")
        copy_btn.clicked.connect(
            lambda: (QApplication.clipboard().setText(stub), copy_btn.setText("Copied ✓")))
        open_btn = QPushButton("Open submission form ↗")
        open_btn.setToolTip("Opens a pre-filled GitHub issue form in your browser.")
        open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(url)))
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        row.addWidget(copy_btn)
        row.addWidget(open_btn)
        row.addStretch(1)
        row.addWidget(close_btn)
        v.addLayout(row)
        dlg.exec()

    def save_report(self):
        if not self.path or (self.report is None and self.batch_result is None):
            return
        import os
        base = Path(self.path).name.replace(":", "").replace("\\", "") or "scan"

        if self.batch_result is not None:
            out_path, _ = QFileDialog.getSaveFileName(
                self, "Save incident report",
                os.path.join(self._last_dir(), base + "_incident.html"), "HTML (*.html)")
            if not out_path:
                return
            self._remember_dir(out_path)
            report_mod.write_incident_report(self.batch_result, out_path,
                                             contact=report_mod.contact_from_env())
            self._on_report_finished(out_path)
            return

        out_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML triage report",
            os.path.join(self._last_dir(), base + "_triage.html"), "HTML (*.html)")
        if not out_path:
            return
        self._remember_dir(out_path)
        do_hash = QMessageBox.question(
            self, "Compute input hash?",
            "Include the input's SHA-256 in the report as proof it was read unmodified?\n\n"
            "This reads the whole input again and can be slow on a large disk.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) == QMessageBox.Yes

        self._set_busy(True)
        self.cancel_token = _CancelToken()
        self.thread = QThread()
        self.worker = HashAndReportWorker(
            self.path, self.report, out_path, do_hash, self.cancel_token)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_report_finished)
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.start()

    @staticmethod
    def _open_path(path: str):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _on_report_finished(self, out_path: str):
        self._set_busy(False)
        if not out_path:
            self.progress_label.setText("Report cancelled.")
            return
        self.progress_label.setText(f"Report saved to {out_path}")
        box = QMessageBox(self)
        box.setWindowTitle("Report saved")
        box.setText(f"Triage report written to:\n{out_path}")
        open_btn = box.addButton("Open report", QMessageBox.AcceptRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is open_btn:
            self._open_path(out_path)

    # ---------------------------------------------------------------- NTFS file extraction

    def open_volume_browser(self):
        if not self.path or not self.report:
            return
        from . import ntfs
        if not ntfs.available():
            QMessageBox.warning(
                self, "NTFS support not installed",
                "Browsing a volume needs the dissect.ntfs package.\n\n"
                "Install it with:  pip install \"rprt[ntfs]\"")
            return
        VolumeBrowserDialog(self, self.path).exec()

    def start_ntfs_extract(self):
        if not self.path or not self.report:
            return
        from . import ntfs
        if not ntfs.available():
            QMessageBox.warning(
                self, "NTFS support not installed",
                "Extracting files from an NTFS volume needs the dissect.ntfs package.\n\n"
                "Install it with:  pip install \"rprt[ntfs]\"")
            return
        # Raw offset from the scan when we have one; otherwise None means "search inside the
        # virtual-disk container" (done in the worker, since it reads through the disk).
        base = self._ntfs_offset(self.report)
        if base is None and not self._is_container():
            return
        dest_dir = QFileDialog.getExistingDirectory(self, "Extract volume files to…",
                                                    self._last_dir())
        if not dest_dir:
            return
        self._remember_dir(dest_dir)
        self._set_busy(True)
        self.cancel_token = _CancelToken()
        self.thread = QThread()
        debug = bool(self._settings.value("debug_mode", False, type=bool))
        self.worker = NtfsExtractWorker(self.path, base, dest_dir, 0, self.cancel_token,
                                        debug=debug)
        self.worker.moveToThread(self.thread)
        self._ntfs_dest = dest_dir
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        # Bound methods, never lambdas: a lambda slot has no receiver QObject, so Qt runs it in
        # the worker thread, and the message boxes these handlers open would then run on the
        # wrong thread -- a cross-thread violation that freezes the UI.
        self.worker.finished.connect(self._on_ntfs_finished)
        self.worker.failed.connect(self._on_ntfs_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.start()

    def _on_ntfs_failed(self, message: str, dest_dir: str = None):
        """Volume extraction could not find a filesystem, or the recovery process stopped on
        damage. Offer to pivot to carving, and to open the diagnostic log if one was written."""
        import os
        if dest_dir is None:
            dest_dir = getattr(self, "_ntfs_dest", None)
        self._set_busy(False)
        self.progress_label.setText("")
        log = os.path.join(dest_dir, "scancrypt-diagnostic.log") if dest_dir else None
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Could not read the filesystem")
        text = message
        if log and os.path.exists(log):
            text += ("\n\nA diagnostic log was saved next to your output folder. It contains "
                     "no file contents and is safe to attach to a bug report:\n" + log)
        box.setText(text)
        carve_btn = box.addButton("Carve loose files…", QMessageBox.AcceptRole) \
            if self._can_carve(self.report) else None
        log_btn = box.addButton("Open diagnostic log", QMessageBox.ActionRole) \
            if (log and os.path.exists(log)) else None
        box.addButton(QMessageBox.Close)
        box.exec()
        clicked = box.clickedButton()
        if carve_btn is not None and clicked is carve_btn:
            self.start_carve()
        elif log_btn is not None and clicked is log_btn:
            self._open_path(log)

    def _on_ntfs_finished(self, outcome, dest_dir=None):
        if dest_dir is None:
            dest_dir = getattr(self, "_ntfs_dest", None)
        self._set_busy(False)
        if outcome is None:
            self.progress_label.setText("Volume extraction cancelled.")
            return
        ok = outcome.get("files_recovered", 0)
        failed = outcome.get("files_failed", 0)
        total = outcome.get("bytes_written", 0)
        method = outcome.get("reader")
        self.progress_label.setText(
            f"Recovered {ok:,} file(s), {human_bytes(total)} to {dest_dir}")
        msg = f"Recovered {ok:,} file(s) ({human_bytes(total)}) to:\n{dest_dir}"
        if method == "vhdx-recovered":
            msg += ("\n\nThe disk's header was encrypted, so the disk was rebuilt from its "
                    "surviving block map and read in its true layout. Spot-check a few files; "
                    "any whose data sat in an encrypted region may be incomplete.")
        elif method == "raw":
            msg += ("\n\nThe disk's header was encrypted, so its payload was read at its "
                    "true offset (the clean path for a fixed-size disk).")
        if failed:
            msg += f"\n\n{failed:,} file(s) could not be extracted (recorded in the summary)."
        box = QMessageBox(self)
        box.setWindowTitle("Volume extraction complete")
        box.setText(msg)
        open_btn = box.addButton("Open folder", QMessageBox.AcceptRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is open_btn:
            self._open_path(dest_dir)

    # ---------------------------------------------------------------- loose-file carving

    def start_carve(self):
        if not self.path or not self.report:
            return
        from . import carve
        if not carve.available():
            QMessageBox.warning(
                self, "PhotoRec not found",
                "Loose-file carving needs PhotoRec (part of TestDisk).\n\n"
                "Install it, or set the SCANCRYPT_PHOTOREC environment variable to the binary.")
            return
        dest_dir = QFileDialog.getExistingDirectory(self, "Carve loose files to…")
        if not dest_dir:
            return
        self._set_busy(True)
        self.cancel_token = _CancelToken()
        self.thread = QThread()
        self.worker = CarveWorker(self.path, self.report, dest_dir, self.cancel_token)
        self.worker.moveToThread(self.thread)
        self._carve_dest = dest_dir
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_carve_finished)   # bound method, not a lambda
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.start()

    def _on_carve_finished(self, summary, dest_dir=None):
        if dest_dir is None:
            dest_dir = getattr(self, "_carve_dest", None)
        self._set_busy(False)
        if summary is None:
            self.progress_label.setText("Carving cancelled.")
            return
        n = summary["file_count"]
        self.progress_label.setText(
            f"Carved {n:,} file(s), {human_bytes(summary['total_bytes'])} to {dest_dir}")
        by = summary.get("by_extension", {})
        top = ", ".join(f"{ext}: {c}" for ext, c in list(by.items())[:10])
        QMessageBox.information(
            self, "Carving complete",
            f"PhotoRec carved {n:,} file(s) ({human_bytes(summary['total_bytes'])}) to:\n"
            f"{dest_dir}" + (f"\n\nBy type: {top}" if top else ""))

    # ---------------------------------------------------------------- shared helpers

    def _on_progress(self, frac: float, label: str):
        # A phase with no measurable fraction (e.g. finding the volume) reports frac<=0.
        # Keep the bar in its animated "busy" state and show the label without a bogus 0%.
        if frac <= 0:
            self.progress_bar.setRange(0, 0)          # indeterminate: marquee animation
            self.progress_label.setText(label)
            return
        if self.progress_bar.maximum() == 0:
            self.progress_bar.setRange(0, 1000)       # first real progress -> determinate
        self.progress_bar.setValue(int(frac * 1000))
        self.progress_label.setText(f"{label}: {frac*100:.1f}%")

    def _on_failed(self, message: str):
        self._set_busy(False)
        QMessageBox.critical(self, "Error", message)

    def cancel_running_job(self):
        if self.cancel_token:
            self.cancel_token.cancel()
        self.cancel_btn.setEnabled(False)

    def _set_busy(self, busy: bool):
        self.scan_btn.setEnabled(not busy and self.path is not None)
        self.another_btn.setEnabled(not busy)
        self.extract_btn.setEnabled(not busy and self.report is not None and self.report.pattern != "fully-encrypted")
        self.report_btn.setEnabled(
            not busy and (self.report is not None or self.batch_result is not None))
        self.ntfs_btn.setEnabled(not busy and self._can_extract_volume(self.report))
        self.browse_btn.setEnabled(not busy and self._can_extract_volume(self.report))
        self.carve_btn.setEnabled(not busy and self._can_carve(self.report))
        self.contribute_btn.setEnabled(not busy and self.report is not None)
        self.cancel_btn.setEnabled(busy)
        if busy:
            # Show the animated (indeterminate) bar the instant a job starts, so the click
            # visibly does something even before the first progress fraction arrives.
            self.progress_bar.setRange(0, 0)
            self.progress_label.setText("Working…")
        else:
            # Stop the marquee, but leave the bar showing where the job actually got to.
            # Resetting to 0 here contradicted the label beside it: a finished scan read
            # "Done: 100.0%" next to an empty 0% bar, which looks like it silently failed.
            # Keeping the last value also tells the truth after a cancel or an error, where
            # the bar stops part-way instead of snapping to either end. A new job re-enters
            # the busy branch above and goes back to the marquee, so nothing goes stale.
            self.progress_bar.setRange(0, 1000)


def _app_icon():
    """The ScanCrypt mark, bundled by PyInstaller (sys._MEIPASS) or from the repo checkout."""
    import os
    from PySide6.QtGui import QIcon
    base = getattr(sys, "_MEIPASS", os.path.join(os.path.dirname(__file__), "..", ".."))
    path = os.path.join(base, "assets", "scancrypt.ico")
    return QIcon(path) if os.path.exists(path) else QIcon()


def _force_light_theme(app):
    """Pin a light Fusion palette regardless of the OS dark-mode setting.

    The layout's panels, banners, and guidance boxes are designed on light
    backgrounds; letting Qt half-inherit a dark system palette produces an
    unreadable mix. Fusion + an explicit palette renders identically everywhere.
    Near-black ink and a larger base font keep it legible on high-DPI screens."""
    from PySide6.QtGui import QPalette
    app.setStyle("Fusion")

    # Bump the base font: the ~9pt Windows default renders small and thin here. Points are
    # DPI-independent, so a fixed floor of 11 is safe on every screen.
    font = app.font()
    base = font.pointSize()
    font.setPointSize(max(base + 2, 11) if base > 0 else 11)
    app.setFont(font)

    INK = "#12151C"        # near-black primary text (was #1A1F29)
    pal = QPalette()
    groups = (QPalette.Active, QPalette.Inactive, QPalette.Disabled)
    colors = {
        QPalette.Window: "#F5F7FA", QPalette.WindowText: INK,
        QPalette.Base: "#FFFFFF", QPalette.AlternateBase: "#EEF1F5",
        QPalette.Text: INK, QPalette.PlaceholderText: "#5B6472",
        QPalette.Button: "#E9EDF2", QPalette.ButtonText: INK,
        QPalette.ToolTipBase: "#FFFFF2", QPalette.ToolTipText: INK,
        QPalette.Highlight: "#1F9C60", QPalette.HighlightedText: "#FFFFFF",
        QPalette.Link: "#146c43", QPalette.BrightText: "#FFFFFF",
    }
    for role, color in colors.items():
        for group in groups:
            pal.setColor(group, role, QColor(color))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        pal.setColor(QPalette.Disabled, role, QColor("#7A828F"))
    app.setPalette(pal)
    # Brand accents: the primary action in signal green, progress in the same green.
    # A slightly larger control font and darker secondary text improve legibility.
    # Enabled controls use near-black ink; the explicit :disabled rules are essential --
    # a blanket colour rule overrides Fusion's own greyed-out look, which would make
    # disabled buttons (e.g. during a scan) still appear active and clickable.
    app.setStyleSheet("""
        QLabel, QRadioButton, QCheckBox, QGroupBox,
        QPlainTextEdit, QMenuBar, QMenu { color: #12151C; }
        QGroupBox::title { color: #12151C; }
        QLabel:disabled, QRadioButton:disabled, QCheckBox:disabled { color: #A3AAB5; }
        QPushButton {
            color: #12151C; background: #E9EDF2; border: 1px solid #C4CBD5;
            border-radius: 3px; padding: 5px 14px; }
        QPushButton:hover:!disabled { background: #DEE3EA; }
        QPushButton:disabled { color: #AAB1BC; background: #F0F2F5; border-color: #DCE0E6; }
        QPushButton#primary {
            background: #37E28C; color: #04120A; font-weight: bold;
            border: 1px solid #1F9C60; padding: 6px 20px; }
        QPushButton#primary:hover:!disabled { background: #5CF0A6; }
        QPushButton#primary:disabled {
            background: #E9EDF2; color: #AAB1BC; border-color: #DCE0E6; }
        QProgressBar { border: 1px solid #C9D0DA; border-radius: 3px;
            background: #EEF1F5; text-align: center; color: #12151C; }
        QProgressBar::chunk { background: #37E28C; }
    """)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("ScanCrypt")
    app.setWindowIcon(_app_icon())
    _force_light_theme(app)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
