"""rprt.supervise — run volume recovery in a separate, memory-capped child process.

Parsing a hostile, half-destroyed disk can, in the worst case, exhaust memory or otherwise
kill the process it runs in. To guarantee the GUI can never be taken down by that, the actual
open-find-extract work runs in a child (the CLI, `--recover-files --jsonl`), and this module
supervises it: streams its JSON progress, caps its memory (a Windows Job Object), and on any
abnormal exit reports a clean outcome instead of letting the app vanish.

The child is the ONLY process that opens and parses the untrusted disk.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading

from . import worker

_EOF = object()   # queue sentinel: the child's stdout closed (it exited)

# Steady-state working set for a large disk (247k-file guest, measured) is ~1 GB: the reader
# cache plus dissect's per-record parsing. The cap sits above that so a legitimate extraction
# is never killed, but well below the multi-GB a genuine runaway allocation would reach, so
# the containment still fires on a real fault.
DEFAULT_MEMORY_LIMIT_MB = 2560


def _cli_prefix():
    """How to launch the CLI worker: the bundled scancrypt exe next to a frozen GUI, or
    `python -m rprt` in development."""
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        for name in ("scancrypt.exe", "scancrypt"):
            cand = os.path.join(exe_dir, name)
            if os.path.exists(cand):
                return [cand]
        raise FileNotFoundError(
            "the scancrypt command-line executable was not found next to the app; "
            "reinstall so both scancrypt.exe and scancrypt-gui.exe are present")
    return [sys.executable, "-m", "rprt"]


def _worker_argv(disk: str, dest: str, min_size: int, debug: bool = False,
                 only_paths_file: str = None):
    tail = [disk, "--recover-files", dest, "--jsonl"]
    if min_size:
        tail += ["--min-file-size", str(min_size)]
    if debug:
        tail.append("--debug")
    if only_paths_file:
        tail += ["--only-paths", only_paths_file]
    return _cli_prefix() + tail


def _list_argv(disk: str, min_size: int = 0):
    tail = [disk, "--list-volume", "--jsonl"]
    if min_size:
        tail += ["--min-file-size", str(min_size)]
    return _cli_prefix() + tail


def _serve_argv(disk: str):
    return _cli_prefix() + [disk, "--serve"]


# --- Windows Job Object containment -----------------------------------------------------
# A Job Object caps the child's memory and kills it if this process dies. On breach the
# kernel terminates the child, which we observe as an abnormal exit and report cleanly.

def _make_windows_job(memory_limit_mb: int):
    import ctypes
    from ctypes import wintypes

    JobObjectExtendedLimitInformation = 9
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(wintypes.ULONG)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    limit = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    cap = memory_limit_mb * 1024 * 1024
    limit.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
    limit.ProcessMemoryLimit = cap
    limit.JobMemoryLimit = cap
    if not k32.SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                       ctypes.byref(limit), ctypes.sizeof(limit)):
        k32.CloseHandle(job)
        return None
    return job


def _assign_windows_job(job, proc) -> None:
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = int(proc._handle)  # subprocess keeps the process HANDLE here on Windows
    k32.AssignProcessToJobObject(job, handle)


def _terminate(proc, job) -> None:
    try:
        if job is not None and os.name == "nt":
            import ctypes
            ctypes.WinDLL("kernel32").TerminateJobObject(job, 1)
        proc.terminate()
    except Exception:  # noqa: BLE001
        pass


def _spawn_and_stream(argv, on_event, cancel_check, memory_limit_mb):
    """Run a CLI worker as a memory-capped child, stream its JSONL events to on_event, and
    return (returncode, events, cancelled, stderr). Shared by every supervised mode so the
    containment (Job Object, cancellation, crash observation) is identical everywhere."""
    # CREATE_NEW_PROCESS_GROUP (clean terminate) | CREATE_NO_WINDOW (the windowed GUI must not
    # flash a console window when it launches the console worker exe).
    creationflags = (0x00000200 | 0x08000000) if os.name == "nt" else 0
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1, creationflags=creationflags)
    job = None
    if os.name == "nt":
        try:
            job = _make_windows_job(memory_limit_mb)
            if job is not None:
                _assign_windows_job(job, proc)
        except Exception:  # noqa: BLE001 -- containment best-effort; supervision still works
            job = None

    lines: "queue.Queue" = queue.Queue()
    err_chunks = []

    def pump_stdout():
        try:
            for line in proc.stdout:
                lines.put(line)
        finally:
            lines.put(None)   # sentinel: stdout closed

    def pump_stderr():
        try:
            for line in proc.stderr:
                err_chunks.append(line)
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=pump_stdout, daemon=True).start()
    threading.Thread(target=pump_stderr, daemon=True).start()

    events = []
    cancelled = False
    while True:
        if cancel_check is not None and cancel_check() and not cancelled:
            cancelled = True
            _terminate(proc, job)
        try:
            line = lines.get(timeout=0.3)   # timeout lets us poll cancel even when silent
        except queue.Empty:
            continue
        if line is None:
            break
        ev = worker.parse_line(line)
        if ev is None:
            continue
        events.append(ev)
        if on_event is not None:
            on_event(ev)

    proc.wait()
    if job is not None and os.name == "nt":
        try:
            import ctypes
            ctypes.WinDLL("kernel32").CloseHandle(job)
        except Exception:  # noqa: BLE001
            pass
    return proc.returncode, events, cancelled, "".join(err_chunks)


def list_files(disk: str, min_size: int = 0, on_file=None, on_event=None, cancel_check=None,
               memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB) -> dict:
    """List the files in the volume inside `disk`, in a supervised child. Calls `on_file(ev)`
    for each {type:file,path,size} event as it streams. Returns an outcome dict
    {status, files, reader, exit_code}. Never raises for a child failure."""
    def relay(ev):
        if ev.get("type") == "file" and on_file is not None:
            on_file(ev)
        if on_event is not None:
            on_event(ev)

    rc, events, cancelled, stderr = _spawn_and_stream(
        _list_argv(disk, min_size), relay, cancel_check, memory_limit_mb)
    by_type = {e["type"]: e for e in events}
    completed = by_type.get("completed", {})
    fatal = by_type.get("fatal", {})
    out = {"files": completed.get("files", sum(1 for e in events if e["type"] == "file")),
           "reader": (by_type.get("started", {}) or {}).get("reader"), "exit_code": rc}
    if cancelled or rc == worker.EXIT_CANCELLED:
        out["status"] = "cancelled"
    elif rc == worker.EXIT_OK and completed:
        out["status"] = "completed"
    elif rc == worker.EXIT_NO_VOLUME or fatal.get("code") == "NO_VOLUME":
        out["status"] = "no_volume"
    elif fatal:
        out["status"] = "error"
        out["detail"] = fatal.get("message", "")
    else:
        out["status"] = "crashed"
        out["detail"] = (stderr.strip().splitlines() or [""])[-1][:500]
    return out


class DirServer:
    """A persistent, memory-capped child that opens the untrusted disk once and answers
    per-directory listing requests. This backs the GUI's lazy browse tree: expanding a folder
    is a request/response round-trip, not a fresh process, so navigation is instant while the
    disk is still only ever opened inside this isolated child. If the child dies, every later
    call returns an error dict and the GUI stays alive -- the same containment as the one-shot
    modes, held open across many requests.

    Not safe for concurrent requests: the caller must serialize them (the GUI issues one tree
    expansion at a time). `open()` must be called and must reach status "ready" before
    list_dir/list_tree are used."""

    def __init__(self, disk: str, memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB):
        self.disk = disk
        self.memory_limit_mb = memory_limit_mb
        self._proc = None
        self._job = None
        self._q: "queue.Queue" = queue.Queue()
        self._err = []
        self._lock = threading.Lock()
        self._next_id = 0
        self._alive = False
        self.status = "new"     # new | ready | no_volume | error | dead
        self.reader = None
        self.base = None
        self.detail = ""

    def open(self, timeout: float = 180.0) -> "DirServer":
        """Spawn the child, wait for its first event, and record the outcome in `status`.
        Returns self so callers can do `srv = DirServer(disk).open()`."""
        creationflags = (0x00000200 | 0x08000000) if os.name == "nt" else 0
        self._proc = subprocess.Popen(
            _serve_argv(self.disk), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, creationflags=creationflags)
        if os.name == "nt":
            try:
                self._job = _make_windows_job(self.memory_limit_mb)
                if self._job is not None:
                    _assign_windows_job(self._job, self._proc)
            except Exception:  # noqa: BLE001 -- containment best-effort
                self._job = None
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

        ev = self._read_event(timeout)
        if ev is None:
            self.status, self.detail = "dead", self._stderr_tail()
        elif ev.get("type") == "ready":
            self._alive, self.status = True, "ready"
            self.reader, self.base = ev.get("reader"), ev.get("base")
        elif ev.get("type") == "fatal":
            self.status = "no_volume" if ev.get("code") == "NO_VOLUME" else "error"
            self.detail = ev.get("message", "")
        else:
            self.status, self.detail = "error", "unexpected first event from browser process"
        return self

    def list_dir(self, path: str = "/"):
        """(entries, error): entries is a list of {name, path, is_dir, size} dicts, or None with
        an error string. Reads a single directory's children in the child."""
        ev = self._request("listdir", path=path)
        if ev.get("type") == "listing":
            return ev.get("entries", []), None
        return None, ev.get("message", "could not list this folder")

    def list_tree(self, path: str, limit: int = 500_000, timeout: float = 600.0):
        """(files, truncated, error): files is a list of [path, size] for every file under
        `path`, or None with an error string. `truncated` is True if the subtree exceeded
        `limit`. Used to extract a whole folder the user picked."""
        ev = self._request("listtree", path=path, timeout=timeout, limit=limit)
        if ev.get("type") == "tree":
            return ev.get("files", []), bool(ev.get("truncated")), None
        return None, False, ev.get("message", "could not enumerate this folder")

    def close(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            with self._lock:
                try:
                    self._proc.stdin.write('{"op":"close"}\n')
                    self._proc.stdin.flush()
                except Exception:  # noqa: BLE001
                    pass
        _terminate(self._proc, self._job)
        if self._job is not None and os.name == "nt":
            try:
                import ctypes
                ctypes.WinDLL("kernel32").CloseHandle(self._job)
            except Exception:  # noqa: BLE001
                pass
        self._alive = False
        if self.status == "ready":
            self.status = "dead"

    # ---- internals ----
    def _request(self, op: str, path=None, timeout: float = 180.0, **extra) -> dict:
        with self._lock:
            if not self._alive:
                return {"type": "op_error", "message": "browser process is not running"}
            self._next_id += 1
            rid = self._next_id
            req = {"op": op, "id": rid}
            if path is not None:
                req["path"] = path
            req.update(extra)
            try:
                self._proc.stdin.write(json.dumps(req) + "\n")
                self._proc.stdin.flush()
            except Exception as exc:  # noqa: BLE001 -- pipe broke: child died mid-request
                self._alive, self.status = False, "dead"
                return {"type": "op_error", "message": f"browser process died: {exc}"}
            while True:
                ev = self._read_event(timeout)
                if ev is None:
                    self._alive, self.status = False, "dead"
                    return {"type": "op_error", "message": "browser process exited"}
                # Serialized, so the next id-tagged response is ours; a fatal ends everything.
                if ev.get("id") == rid or ev.get("type") == "fatal":
                    return ev

    def _read_event(self, timeout: float):
        try:
            item = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        return None if item is _EOF else item

    def _pump_stdout(self):
        try:
            for line in self._proc.stdout:
                ev = worker.parse_line(line)
                if ev is not None:
                    self._q.put(ev)
        finally:
            self._q.put(_EOF)

    def _pump_stderr(self):
        try:
            for line in self._proc.stderr:
                self._err.append(line)
                if len(self._err) > 200:
                    del self._err[:100]
        except Exception:  # noqa: BLE001
            pass

    def _stderr_tail(self) -> str:
        return "".join(self._err).strip().splitlines()[-1][:500] if self._err else ""


def recover(disk: str, dest: str, min_size: int = 0,
            memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
            on_event=None, cancel_check=None, debug: bool = False, only_paths=None) -> dict:
    """Run recovery in a supervised child and return an outcome dict:
        {status: completed|no_volume|cancelled|crashed|error,
         files_recovered, files_failed, bytes_written, exit_code, reader, detail, diag_log}
    `on_event(ev)` receives each protocol event; `cancel_check()` truthy terminates the child.
    `only_paths`, if given, is an iterable of volume paths to extract (the rest are skipped).
    Never raises for a child failure: an abnormal exit becomes status "crashed"."""
    os.makedirs(dest, exist_ok=True)
    only_file = None
    if only_paths:
        only_file = os.path.join(dest, ".scancrypt-selected-paths.txt")
        with open(only_file, "w", encoding="utf-8") as f:
            f.write("\n".join(only_paths))
    argv = _worker_argv(disk, dest, min_size, debug, only_file)
    rc, events, cancelled, stderr = _spawn_and_stream(argv, on_event, cancel_check,
                                                      memory_limit_mb)
    if only_file:
        try:
            os.remove(only_file)
        except OSError:
            pass

    outcome = _classify(rc, events, cancelled, stderr, dest)
    outcome["diag_log"] = worker.diag_path(dest)
    # The child is dead now, so appending is race-free. On an abnormal exit its own diagnostic
    # writing may have been cut short; record the supervisor's view (exit code + captured
    # stderr, which is where a native faulthandler trace lands) so one file has the whole story.
    if outcome["status"] in ("crashed", "error"):
        _append_supervisor_diag(dest, outcome, stderr)
    return outcome


def _append_supervisor_diag(dest, outcome, stderr):
    try:
        with open(worker.diag_path(dest), "a", encoding="utf-8") as f:
            f.write("\n== supervisor ==\n")
            f.write(f"  status: {outcome['status']}\n")
            f.write(f"  exit_code: {outcome['exit_code']}\n")
            if stderr.strip():
                f.write("  child stderr / native traceback:\n")
                for line in stderr.strip().splitlines()[-100:]:
                    f.write(f"    {line}\n")
    except OSError:
        pass


def _classify(exit_code, events, cancelled, stderr, dest) -> dict:
    by_type = {e["type"]: e for e in events}
    completed = by_type.get("completed", {})
    fatal = by_type.get("fatal", {})
    # Fall back to the on-disk summary if the pipe was lost before the completed event.
    if not completed:
        summary = _read_summary(dest)
        if summary:
            completed = summary

    out = {
        "files_recovered": completed.get("files_recovered", 0),
        "files_failed": completed.get("files_failed", 0),
        "bytes_written": completed.get("bytes_written", 0),
        "reader": completed.get("reader") or (by_type.get("started", {}) or {}).get("reader"),
        "exit_code": exit_code,
        "detail": "",
    }

    if cancelled or exit_code == worker.EXIT_CANCELLED:
        out["status"] = "cancelled"
    elif exit_code == worker.EXIT_OK and completed:
        out["status"] = "completed"
    elif exit_code == worker.EXIT_NO_VOLUME or fatal.get("code") == "NO_VOLUME":
        out["status"] = "no_volume"
    elif fatal:
        out["status"] = "error"
        out["detail"] = fatal.get("message", "")
    else:
        # Non-zero exit with no clean fatal event == the child was killed (OOM / job / native
        # crash). This is the case containment exists for: report it, keep the GUI alive.
        out["status"] = "crashed"
        out["detail"] = (stderr.strip().splitlines() or [""])[-1][:500]
    return out


def _read_summary(dest):
    import json
    path = os.path.join(dest, "scancrypt-recovery-summary.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
