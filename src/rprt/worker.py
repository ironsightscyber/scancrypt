"""rprt.worker — the newline-delimited JSON protocol spoken by the recovery worker.

The GUI runs volume recovery in a separate, memory-capped child process (the CLI exe) so
that parsing a hostile, half-destroyed disk can never take down the app. The child streams
structured events on stdout; the parent (see rprt.supervise) reads them for progress and, on
a crash, reports a clean error instead of vanishing.

Design rules:
  - one JSON object per line, flushed immediately;
  - a protocol version on every event ("v");
  - no victim *file contents* ever appear in a message (paths are recovery-relative);
  - structured error codes, not free text, where practical;
  - a final summary is also written to disk, so a lost pipe still leaves a record.

This module has no third-party imports so it stays importable in the slim CLI build.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

PROTOCOL_VERSION = 1

DIAG_FILENAME = "scancrypt-diagnostic.log"

# Strip anything that could identify a victim from a disk name before it goes in a log that
# may be shared publicly: the ransom-id and attacker-address groups Makop appends in [..],
# and the base filename itself. What survives is the structure we actually need for triage.
_BRACKET = re.compile(r"\[[^\]]*\]")


def redact_disk_name(path: str) -> str:
    """A shareable label for a disk: its extension chain with bracketed victim/attacker groups
    and the base name removed (e.g. 'Payroll Database.vhdx.[id].[addr].ndm448' -> '*.vhdx.ndm448')."""
    name = os.path.basename(path)
    name = _BRACKET.sub("", name)
    parts = [p for p in name.split(".") if p]
    exts = parts[1:] if len(parts) > 1 else parts        # drop the base name, keep extensions
    return "*." + ".".join(exts) if exts else "*"


def diag_path(dest_dir: str) -> str:
    return os.path.join(dest_dir, DIAG_FILENAME)


class DiagLog:
    """A best-effort diagnostic log for a recovery run. Written to the output folder so it is
    easy to find and attach to a bug report. Contains no file *contents*; file paths appear
    only in verbose mode (they can carry victim filenames). Never raises to the caller."""

    def __init__(self, path: str, verbose: bool = False):
        self.path = path
        self.verbose = verbose
        self._fh = None
        try:
            self._fh = open(path, "w", encoding="utf-8", buffering=1)
        except OSError:
            self._fh = None

    @property
    def file(self):
        return self._fh

    def line(self, msg: str = "") -> None:
        if self._fh is not None:
            try:
                self._fh.write(f"{time.strftime('%H:%M:%S')}  {msg}\n")
            except (OSError, ValueError):
                pass

    def section(self, title: str) -> None:
        self.line()
        self.line(f"== {title} ==")

    def kv(self, **fields) -> None:
        for k, v in fields.items():
            self.line(f"  {k}: {v}")

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

# Process exit codes (also used by the supervisor to classify outcomes).
EXIT_OK = 0
EXIT_NO_VOLUME = 2        # no readable NTFS volume found
EXIT_FATAL = 3           # an unexpected, non-recoverable error
EXIT_CANCELLED = 130     # cancelled (SIGINT / control)


class Emitter:
    """Writes protocol events. When `jsonl` is false it stays silent (the CLI prints its own
    human-readable output instead), so the same code path serves both interactive use and the
    supervised child."""

    def __init__(self, stream=None, jsonl: bool = False):
        self._stream = stream or sys.stdout
        self._jsonl = jsonl

    def emit(self, type: str, **fields) -> None:
        if not self._jsonl:
            return
        line = json.dumps({"v": PROTOCOL_VERSION, "type": type, **fields},
                          separators=(",", ":"), default=str)
        self._stream.write(line + "\n")
        self._stream.flush()


def write_summary(dest_dir: str, summary: dict) -> str:
    """Persist the final summary next to the recovered files, so the outcome survives even if
    the parent never read the last stdout line. Returns the path written."""
    path = os.path.join(dest_dir, "scancrypt-recovery-summary.json")
    try:
        os.makedirs(dest_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"v": PROTOCOL_VERSION, **summary}, f, indent=2, default=str)
    except OSError:
        pass
    return path


def parse_line(line: str):
    """Parse one protocol line for the supervisor. Returns the event dict, or None for a
    blank or malformed line (which the parent records but does not act on)."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or "type" not in obj:
        return None
    return obj
