"""rprt.carve — orchestrate PhotoRec for loose-file carving of the recoverable region.

For generic files (not a disk image or a database we can extract structurally), the right
move is to hand the intact byte-range to a mature signature carver rather than reinvent
one. PhotoRec (part of TestDisk) is the standard choice. This module finds it, runs it
non-interactively against the recoverable data, and summarises what it recovered.

Two modes:
  - carve the source directly (PhotoRec skips the encrypted region as unrecognisable), or
  - isolate the intact byte-range to a temp file first (via the engine) and carve only
    that -- more precise, at the cost of the intermediate file's disk space.

PhotoRec is an optional, external dependency; everything else in rprt works without it.
This module never writes to the scanned input -- only to the chosen output directory.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from collections import Counter
from typing import Callable, List, Optional

ProgressFn = Optional[Callable[[float, str], None]]
LogFn = Optional[Callable[[str], None]]

# Env override lets a user point at a specific binary; otherwise search PATH then a few
# common Windows install locations for the TestDisk/PhotoRec distribution.
_ENV_OVERRIDE = "RPRT_PHOTOREC"
_WINDOWS_HINTS = [
    r"C:\Program Files\testdisk\photorec_win.exe",
    r"C:\Program Files (x86)\testdisk\photorec_win.exe",
    r"C:\testdisk\photorec_win.exe",
]


def find_photorec() -> Optional[str]:
    """Locate the PhotoRec binary: $RPRT_PHOTOREC, then PATH, then common Windows dirs."""
    override = os.environ.get(_ENV_OVERRIDE)
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    for name in ("photorec", "photorec.exe", "photorec_win.exe", "photorec_static"):
        found = shutil.which(name)
        if found:
            return found
    for hint in _WINDOWS_HINTS:
        if os.path.isfile(hint):
            return hint
    return None


def available() -> bool:
    return find_photorec() is not None


def build_command(photorec: str, image: str, dest_prefix: str,
                  whole_space: bool = True, file_types: Optional[List[str]] = None) -> List[str]:
    """Construct PhotoRec's non-interactive (/cmd) argv.

    dest_prefix is the recovery directory prefix; PhotoRec appends .1, .2, ... to it.
    whole_space carves the entire input (vs only free space). file_types, if given,
    restricts carving to those extensions (e.g. ["jpg", "pdf", "docx"]); otherwise every
    known signature is enabled.
    """
    parts = ["partition_none"]
    if file_types:
        # disable everything, then re-enable just the requested extensions
        parts += ["options", "fileopt", "everything", "disable"]
        for t in file_types:
            parts += [t, "enable"]
    parts.append("wholespace" if whole_space else "freespace")
    parts.append("search")
    return [photorec, "/log", "/d", dest_prefix, "/cmd", image, ",".join(parts)]


def collect_recovered(dest_prefix: str) -> dict:
    """Summarise what PhotoRec wrote under <dest_prefix>.1, .2, ... -- file count, total
    bytes, and a breakdown by extension."""
    parent = os.path.dirname(dest_prefix) or "."
    base = os.path.basename(dest_prefix)
    dirs = []
    if os.path.isdir(parent):
        for entry in sorted(os.listdir(parent)):
            full = os.path.join(parent, entry)
            if os.path.isdir(full) and entry.startswith(base + "."):
                dirs.append(full)

    by_ext = Counter()
    total_bytes = 0
    file_count = 0
    for d in dirs:
        for root, _sub, files in os.walk(d):
            for fn in files:
                if fn in ("report.xml",):
                    continue
                fp = os.path.join(root, fn)
                try:
                    total_bytes += os.path.getsize(fp)
                except OSError:
                    continue
                file_count += 1
                ext = os.path.splitext(fn)[1].lstrip(".").lower() or "(none)"
                by_ext[ext] += 1
    return {
        "recovery_dirs": dirs,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "by_extension": dict(by_ext.most_common()),
    }


def carve(image: str, out_dir: str, whole_space: bool = True,
          file_types: Optional[List[str]] = None, log: LogFn = None,
          cancel_check=None, timeout: Optional[int] = None) -> dict:
    """Run PhotoRec against `image`, writing recovered files under `out_dir`, and return
    a summary from collect_recovered(). Raises RuntimeError if PhotoRec isn't found."""
    photorec = find_photorec()
    if photorec is None:
        raise RuntimeError(
            "PhotoRec not found. Install TestDisk/PhotoRec, or set RPRT_PHOTOREC to the "
            "binary path.")
    os.makedirs(out_dir, exist_ok=True)
    dest_prefix = os.path.join(out_dir, "recup_dir")
    cmd = build_command(photorec, image, dest_prefix, whole_space, file_types)

    if log:
        log("running: " + " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    try:
        for line in proc.stdout:
            if log:
                log(line.rstrip())
            if cancel_check is not None and cancel_check():
                proc.terminate()
                break
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    finally:
        if proc.stdout:
            proc.stdout.close()

    summary = collect_recovered(dest_prefix)
    summary["returncode"] = proc.returncode
    summary["cancelled"] = bool(cancel_check is not None and cancel_check())
    return summary


def carve_recoverable(path: str, report, out_dir: str, isolate_intact: bool = True,
                      keep_intact: bool = False, progress: ProgressFn = None,
                      log: LogFn = None, cancel_check=None) -> dict:
    """Carve the recoverable region of `path`.

    isolate_intact=True (default when the scan found a front boundary): extract the intact
    byte-range to a temp file with the engine, then carve only that -- so PhotoRec never
    wastes time on, or mis-carves from, the encrypted bytes. Otherwise carve `path`
    directly and let PhotoRec skip the unrecognisable region itself.
    """
    from . import engine

    if report is not None and report.pattern == "fully-encrypted":
        raise ValueError("nothing to carve: the input reads as fully encrypted")

    os.makedirs(out_dir, exist_ok=True)
    target = path
    temp_file = None
    try:
        if isolate_intact and report is not None and report.boundary_offset:
            temp_file = os.path.join(out_dir, "_intact_region.bin")
            if progress:
                progress(0.0, "Isolating recoverable region")
            engine.extract_intact_ranges(path, report, temp_file,
                                         progress=progress, cancel_check=cancel_check)
            target = temp_file
        summary = carve(target, out_dir, log=log, cancel_check=cancel_check)
    finally:
        if temp_file and not keep_intact and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass
    if progress:
        progress(1.0, "Done")
    return summary
