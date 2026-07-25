"""rprt.cli — command-line entry point (kept alongside the GUI for scripting/CI use)."""
import argparse
import faulthandler
import json
import os
import sys

from . import engine

# Dump a native traceback if the process is killed by a fatal signal (segfault, abort). On a
# hostile/half-destroyed disk the parser can, in principle, crash below the Python level; this
# turns a silent death into a diagnosable stack. Guard on stderr: a windowed spawn can have
# sys.stderr = None, where enable() would raise.
if sys.stderr is not None:
    faulthandler.enable()


def _contact_from_args(args):
    """Optional IronSights-style contact block on the report. CLI flags win; otherwise fall back
    to environment variables so a firm can configure it once. None keeps the report neutral."""
    from . import report as report_mod
    contact = report_mod.contact_from_env()
    if args.firm_name:
        return {"firm": args.firm_name, "url": args.firm_url or "",
                "blurb": args.firm_blurb or ""}
    if contact and (args.firm_url or args.firm_blurb):
        return {**contact, "url": args.firm_url or contact.get("url", ""),
                "blurb": args.firm_blurb or contact.get("blurb", "")}
    return contact


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rprt",
        description="Ransomware partial-recovery entropy mapper. Read-only scan; "
                     "never modifies the input.",
    )
    ap.add_argument("path", help="file, disk image, or (Windows, as Administrator) a "
                                 "raw device path like \\\\.\\PhysicalDrive1 or \\\\.\\D:")
    ap.add_argument("--full", action="store_true", help="force full block-by-block scan")
    ap.add_argument("--boundary-only", action="store_true",
                    help="accept the fast front-boundary result and never escalate to a full "
                         "block scan, even if high-entropy content is seen past the boundary "
                         "(avoids a whole-file read on a large slow disk)")
    ap.add_argument("--block-size", type=int, default=8192)
    ap.add_argument("--sample-size", type=int, default=65536)
    ap.add_argument("--json", metavar="FILE", help="write full report as JSON")
    ap.add_argument("--report", metavar="FILE", help="write a standalone HTML triage report")
    ap.add_argument("--hash", action="store_true",
                    help="compute the input SHA-256 for the report (slow on large disks)")
    ap.add_argument("--extract", metavar="FILE", help="write recovered intact bytes here")
    ap.add_argument("--extract-volume", metavar="FILE",
                    help="cut a detected intact NTFS volume out of the scanned image as a "
                         "standalone partition image (opens in 7-Zip and forensic tools)")
    ap.add_argument("--list-files", action="store_true",
                    help="list files in an intact NTFS volume found in the recoverable region")
    ap.add_argument("--extract-files", metavar="DIR",
                    help="extract files from the intact NTFS volume to DIR (structure-aware)")
    ap.add_argument("--ntfs-offset", type=lambda x: int(x, 0),
                    help="byte offset of the NTFS boot sector (else auto-detected from the scan)")
    ap.add_argument("--min-file-size", type=int, default=0,
                    help="only list/extract volume files at least this many bytes")
    ap.add_argument("--recover-files", metavar="DIR",
                    help="recover files from a virtual disk (VHDX/VHD/VMDK) to DIR, including "
                         "one whose header the ransomware encrypted: locates the NTFS volume "
                         "(rebuilding a dynamic disk from its surviving block map) and extracts")
    ap.add_argument("--jsonl", action="store_true",
                    help="with --recover-files, emit newline-delimited JSON progress events on "
                         "stdout (used by the GUI when it supervises this as a child process)")
    ap.add_argument("--debug", action="store_true",
                    help="with --recover-files, write a verbose diagnostic log (includes file "
                         "paths, which may contain filenames from the disk)")
    ap.add_argument("--list-volume", action="store_true",
                    help="list every file in the NTFS volume inside a virtual disk (streams "
                         "path+size); used by the GUI's browse/search over the volume")
    ap.add_argument("--serve", action="store_true",
                    help="open the volume once and answer directory-listing requests read as "
                         "JSON lines on stdin; used by the GUI's lazy browse tree so a folder "
                         "is read only when it is expanded")
    ap.add_argument("--only-paths", metavar="FILE",
                    help="with --recover-files, extract only the volume paths listed in FILE "
                         "(one per line); used by the GUI's extract-selected flow")
    ap.add_argument("--validate-sql", action="store_true",
                    help="validate the path as a recovered SQL Server MDF/NDF at the page "
                         "level (recovery-quality check) instead of an entropy scan")
    ap.add_argument("--sample", type=int, default=1,
                    help="with --validate-sql, check every Nth page (default 1 = all)")
    ap.add_argument("--fingerprint", action="store_true",
                    help="emit a privacy-safe family signature stub for this encrypted file "
                         "(extension, magic-candidate bytes, encryption pattern, nearby ransom "
                         "note) and a pre-filled GitHub issue link, to help ScanCrypt recognise "
                         "a new strain. Reads no file contents.")
    ap.add_argument("--carve", metavar="DIR",
                    help="carve loose files from the recoverable region into DIR with PhotoRec")
    ap.add_argument("--carve-source", action="store_true",
                    help="with --carve, run PhotoRec on the whole input instead of first "
                         "isolating the intact byte-range")
    ap.add_argument("--csv", metavar="FILE",
                    help="with a directory path (batch mode), write a per-file CSV")
    ap.add_argument("--min-size", type=int, default=1,
                    help="batch mode: skip files smaller than this many bytes")
    ap.add_argument("--audit-log", metavar="FILE",
                    help="write a tamper-evident (hash-chained) JSONL audit trail; enables "
                         "before/after integrity hashing of the input")
    ap.add_argument("--case-id", help="case identifier for the audit log / report")
    ap.add_argument("--examiner", help="examiner name for the audit log / report")
    ap.add_argument("--evidence-id", help="evidence identifier for the audit log / report")
    ap.add_argument("--firm-name", help="add a 'recovery assistance' contact block to the HTML "
                    "report (defaults to $RPRT_FIRM_NAME)")
    ap.add_argument("--firm-url", help="link for the --firm-name contact block "
                    "(defaults to $RPRT_FIRM_URL)")
    ap.add_argument("--firm-blurb", help="custom text for the contact block "
                    "(defaults to $RPRT_FIRM_BLURB)")
    args = ap.parse_args(argv)

    contact = _contact_from_args(args)

    # Progress rendering. On a TTY: overwrite one line in place (throttled to 0.1% so we
    # don't flush thousands of identical frames). Piped/redirected (nohup, CI, a log file):
    # a bare '\r' just concatenates thousands of updates onto one unreadable mega-line, so
    # instead emit a newline-terminated line only when the phase changes or every 5%.
    _tty = sys.stderr is not None and sys.stderr.isatty()
    _prog = {"key": None}

    def progress(frac, label):
        if sys.stderr is None:
            return
        pct = frac * 100
        if _tty:
            key = (label, round(pct, 1))
            if key == _prog["key"]:
                return
            _prog["key"] = key
            print(f"\r{label}: {pct:5.1f}%", end="", file=sys.stderr, flush=True)
        else:
            key = (label, int(pct // 5))
            if key == _prog["key"]:
                return
            _prog["key"] = key
            print(f"{label}: {pct:.0f}%", file=sys.stderr, flush=True)

    # Browse mode: list the files in the volume (streamed), for the GUI's search/extract UI.
    if args.list_volume:
        return _handle_list_volume(args)

    # Lazy-browse server: open the volume once and answer per-directory listing requests, so
    # the GUI's tree reads a folder only when it is expanded.
    if args.serve:
        return _handle_serve(args)

    # Recovered-volume file extraction is a distinct mode: it locates the NTFS volume itself
    # (find_ntfs_volume, incl. the encrypted-header rebuild) rather than using a prior scan.
    if args.recover_files is not None:
        return _handle_recover_files(args)

    # A directory path means incident-level batch mode: scan every file and aggregate.
    if os.path.isdir(args.path):
        return _handle_batch(args, progress)

    if not engine.is_scannable(args.path):
        print(f"error: {args.path} is not a readable file or raw device path", file=sys.stderr)
        return 1

    if args.fingerprint:
        from . import fingerprint
        fp = fingerprint.build(args.path)
        print(fingerprint.render_text(fp))
        if args.json:
            with open(args.json, "w") as f:
                json.dump({**fp.to_dict(), "issue_url": fingerprint.issue_url(fp),
                           "yaml_stub": fingerprint.to_yaml_stub(fp)}, f, indent=2)
            print(f"\nfingerprint written to {args.json}", file=sys.stderr)
        return 0

    if args.validate_sql:
        from . import sqlpages
        result = sqlpages.validate(args.path, sample_every=max(args.sample, 1), progress=progress)
        print(file=sys.stderr)
        print(json.dumps(result.to_dict(), indent=2))
        if args.json:
            with open(args.json, "w") as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"validation written to {args.json}", file=sys.stderr)
        return 0

    # Optional forensic audit trail: hash the input up front (proof-of-state) and open a
    # hash-chained log; integrity is re-verified at the end.
    audit = None
    before_hash = None
    if args.audit_log or args.case_id or args.examiner or args.evidence_id:
        from . import forensics
        case = forensics.CaseContext(case_id=args.case_id or "", examiner=args.examiner or "",
                                     evidence_id=args.evidence_id or "")
        audit = forensics.AuditLog(path=args.audit_log, case=case)
        before_hash = forensics.sha256_file(args.path, progress=progress)
        print(file=sys.stderr)
        audit.input_opened(args.path, sha256=before_hash)

    report = engine.scan(
        args.path, full=args.full, sample_size=args.sample_size,
        block_size=args.block_size, progress=progress,
        boundary_only=args.boundary_only,
    )
    print(file=sys.stderr)
    if audit:
        audit.record("scan_complete", pattern=report.pattern,
                     recoverable_bytes=report.recoverable_bytes,
                     recoverable_pct=report.recoverable_pct,
                     family=(report.family or {}).get("family"))

    print(json.dumps(report.to_dict(), indent=2))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"full report written to {args.json}", file=sys.stderr)

    if args.report:
        from . import report as report_mod
        sha = before_hash
        if sha is None and args.hash:
            sha = report_mod.sha256_of_input(args.path, progress=progress)
            print(file=sys.stderr)
        report_mod.write_html_report(
            args.path, report, args.report, sha256=sha,
            case=(audit.case.to_dict() if audit else None),
            contact=contact,
            scan_params={"scan mode": "full" if args.full else "adaptive",
                         "block size": args.block_size, "sample size": args.sample_size},
        )
        print(f"HTML triage report written to {args.report}", file=sys.stderr)

    rc = 0
    if args.extract:
        if report.pattern in ("fully-encrypted",):
            print("nothing to extract: file reads as fully encrypted", file=sys.stderr)
            rc = 1
        else:
            written = engine.extract_intact_ranges(args.path, report, args.extract, progress=progress)
            print(file=sys.stderr)
            print(f"wrote {written:,} recovered bytes to {args.extract}", file=sys.stderr)
            if audit:
                from . import forensics
                out_hash = forensics.sha256_file(args.extract)
                audit.output_written(args.extract, written, sha256=out_hash)

    if rc == 0 and args.extract_volume:
        ntfs_off = next((f["offset"] for f in report.formats if "NTFS" in f["name"]), None)
        if ntfs_off is None:
            print("no intact NTFS volume was detected in this scan; --extract-volume "
                  "applies to disk images and raw devices", file=sys.stderr)
            rc = 1
        else:
            length = engine.ntfs_volume_length(args.path, ntfs_off)
            written = engine.extract_range(args.path, ntfs_off, length,
                                           args.extract_volume, progress=progress)
            print(file=sys.stderr)
            print(f"wrote {written:,}-byte NTFS volume image to {args.extract_volume} "
                  f"(open it with 7-Zip or forensic tools)", file=sys.stderr)
            if audit:
                from . import forensics
                audit.output_written(args.extract_volume, written,
                                     sha256=forensics.sha256_file(args.extract_volume))

    if rc == 0 and (args.list_files or args.extract_files):
        rc = _handle_ntfs(args, report, progress)

    if rc == 0 and args.carve:
        rc = _handle_carve(args, report, progress)

    _finalize_audit(audit, args.path, before_hash, progress)
    return rc


def _finalize_audit(audit, path, before_hash, progress):
    """Re-hash the input to prove it was never modified, record the result, and seal the
    hash-chained log."""
    if not audit:
        return
    from . import forensics
    after_hash = forensics.sha256_file(path, progress=progress)
    print(file=sys.stderr)
    audit.integrity_verified(path, before_hash, after_hash)
    audit.session_end()
    status = "UNCHANGED" if before_hash == after_hash else "MODIFIED (!)"
    print(f"evidence integrity: input {status} (sha256 before == after: "
          f"{before_hash == after_hash}); audit-log seal {audit.seal()[:16]}…",
          file=sys.stderr)
    if audit.path:
        print(f"tamper-evident audit log written to {audit.path}", file=sys.stderr)


def _handle_batch(args, progress):
    from . import batch
    result = batch.scan_tree(args.path, min_size=args.min_size, full=args.full,
                             do_hash=args.hash, progress=progress)
    print(file=sys.stderr)

    summary = {k: v for k, v in result.to_dict().items() if k != "files"}
    print(json.dumps(summary, indent=2))
    print(f"\n{result.recoverable_pct:.1f}% of {result.total_bytes:,} bytes recoverable "
          f"across {result.scanned:,} file(s)", file=sys.stderr)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"full per-file JSON written to {args.json}", file=sys.stderr)
    if args.csv:
        batch.write_csv(result, args.csv)
        print(f"per-file CSV written to {args.csv}", file=sys.stderr)
    if args.report:
        from . import report as report_mod
        report_mod.write_incident_report(result, args.report, contact=_contact_from_args(args))
        print(f"incident HTML report written to {args.report}", file=sys.stderr)
    return 0


def _handle_carve(args, report, progress):
    from . import carve
    if not carve.available():
        print("PhotoRec not found. Install TestDisk/PhotoRec or set RPRT_PHOTOREC to the "
              "binary path.", file=sys.stderr)
        return 1
    if report.pattern == "fully-encrypted":
        print("nothing to carve: the input reads as fully encrypted", file=sys.stderr)
        return 1
    try:
        summary = carve.carve_recoverable(
            args.path, report, args.carve,
            isolate_intact=not args.carve_source,
            progress=progress, log=lambda line: print(line, file=sys.stderr))
    except Exception as exc:  # noqa: BLE001
        print(f"carving failed: {exc}", file=sys.stderr)
        return 1
    print(file=sys.stderr)
    print(f"carved {summary['file_count']:,} file(s), {summary['total_bytes']:,} bytes "
          f"into {args.carve}", file=sys.stderr)
    if summary["by_extension"]:
        top = ", ".join(f"{ext}:{n}" for ext, n in list(summary["by_extension"].items())[:12])
        print(f"  by type: {top}", file=sys.stderr)
    return 0


def _ntfs_offset_from(args, report):
    """Resolve the NTFS volume offset: explicit --ntfs-offset, else the first NTFS
    finding from format detection, else a boot-sector scan of the recoverable region."""
    if args.ntfs_offset is not None:
        return args.ntfs_offset
    for f in report.formats:
        if "NTFS" in f["name"]:
            return f["offset"]
    from . import ntfs
    return ntfs.find_ntfs_boot_sector(args.path)


def _handle_list_volume(args):
    """List every file in the NTFS volume inside a virtual disk, streaming path+size events.
    The GUI runs this as a supervised child to populate its browse/search view; like
    _handle_recover_files it never raises out, so a crash is the OS killing this process."""
    from . import ntfs, worker

    em = worker.Emitter(jsonl=args.jsonl)
    if not ntfs.available():
        em.emit("fatal", code="NTFS_UNAVAILABLE", message="dissect.ntfs not installed")
        if not args.jsonl:
            print("NTFS support needs dissect.ntfs", file=sys.stderr)
        return worker.EXIT_FATAL
    try:
        method = ntfs.disk_read_method(args.path)
        em.emit("started", reader=method)
        em.emit("phase", name="locate_volume")
        base = ntfs.find_ntfs_volume(args.path)
        if base is None:
            em.emit("fatal", code="NO_VOLUME", message="no readable NTFS volume")
            if not args.jsonl:
                print("no readable NTFS volume found in this disk", file=sys.stderr)
            return worker.EXIT_NO_VOLUME
        em.emit("phase", name="list")
        count = 0
        coverage = None
        with ntfs.MountedNTFS(args.path, base) as m:
            total = ntfs._total_mft_records(m.fs)
            for idx, seg in ntfs._iter_records(m.fs):
                if args.jsonl and total and idx % 4000 == 0:
                    em.emit("progress", fraction=round(min(idx / total, 0.99), 4), files=count)
                got = ntfs._file_from_segment(seg, args.min_file_size)
                if got is None:
                    continue
                vpath, size = got
                count += 1
                em.emit("file", path=vpath, size=size)
                if not args.jsonl:
                    print(f"{size:>14,}  {vpath}")
            coverage = ntfs.mft_coverage(m.fs)
        missing = (coverage or {}).get("missing_in_range", 0)
        if missing:
            em.emit("warning", code="PARTIAL_MFT", missing_records=missing,
                    present_records=coverage.get("present_records"),
                    message="listing is partial: some MFT records were unrecoverable")
        em.emit("completed", files=count, partial=bool(missing),
                mft_missing_records=missing)
        if not args.jsonl:
            if missing:
                print(f"WARNING: listing is PARTIAL -- {missing:,} MFT record(s) within the "
                      f"used range were unrecoverable (their disk blocks did not survive), so "
                      f"some files are missing from this list.", file=sys.stderr)
            print(f"{count:,} file(s) in the volume"
                  f"{' (partial)' if missing else ''}", file=sys.stderr)
        return worker.EXIT_OK
    except KeyboardInterrupt:
        em.emit("fatal", code="CANCELLED", message="cancelled")
        return worker.EXIT_CANCELLED
    except Exception as exc:  # noqa: BLE001
        em.emit("fatal", code="ERROR", message=str(exc))
        if not args.jsonl:
            print(f"listing failed: {exc}", file=sys.stderr)
        return worker.EXIT_FATAL


def _handle_serve(args):
    """Open the NTFS volume once and answer directory-listing requests read as JSON lines on
    stdin, one response line per request. This backs the GUI's lazy browse tree: the untrusted
    disk is parsed a single time in this isolated child, and a folder's children are read only
    when the tree asks for them. Like the other supervised modes it never raises out -- a crash
    is the OS killing this process, which the parent (rprt.supervise) reports cleanly.

    Requests, one JSON object per line:
        {"op":"listdir","id":N,"path":"/Users"}    -> {"type":"listing","id":N,...,"entries":[...]}
        {"op":"listtree","id":N,"path":"/Users/x"} -> {"type":"tree","id":N,...,"files":[[p,s],...]}
        {"op":"close"}                             -> exit (stdin EOF also exits cleanly)."""
    from . import ntfs, worker

    em = worker.Emitter(jsonl=True)
    if not ntfs.available():
        em.emit("fatal", code="NTFS_UNAVAILABLE", message="dissect.ntfs not installed")
        return worker.EXIT_FATAL
    try:
        method = ntfs.disk_read_method(args.path)
        base = ntfs.find_ntfs_volume(args.path)
        if base is None:
            em.emit("fatal", code="NO_VOLUME", message="no readable NTFS volume")
            return worker.EXIT_NO_VOLUME
        with ntfs.MountedNTFS(args.path, base) as m:
            em.emit("ready", reader=method, base=base)
            for line in sys.stdin:                    # blocks until the parent sends a request
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except (ValueError, TypeError):
                    continue
                op = req.get("op")
                if op == "close":
                    break
                rid = req.get("id")
                path = req.get("path") or "/"
                try:
                    if op == "listdir":
                        entries = [{"name": e["name"], "path": e["path"],
                                    "is_dir": e["is_dir"], "size": e["size"]}
                                   for e in ntfs.list_dir(m.fs, path)]
                        em.emit("listing", id=rid, path=path, entries=entries)
                    elif op == "listtree":
                        cap = int(req.get("limit") or 2_000_000)
                        files, truncated = [], False
                        for p, s in ntfs.list_tree(m.fs, path):
                            files.append([p, s])
                            if len(files) >= cap:
                                truncated = True
                                break
                        em.emit("tree", id=rid, path=path, files=files, truncated=truncated)
                    else:
                        em.emit("op_error", id=rid, message=f"unknown op {op!r}")
                except Exception as exc:  # noqa: BLE001 -- one bad request can't kill the server
                    em.emit("op_error", id=rid, path=path, message=str(exc))
        return worker.EXIT_OK
    except KeyboardInterrupt:
        return worker.EXIT_CANCELLED
    except Exception as exc:  # noqa: BLE001
        em.emit("fatal", code="ERROR", message=str(exc))
        return worker.EXIT_FATAL


def _handle_recover_files(args):
    """Recover files from a virtual disk to a directory, emitting the worker protocol.

    This is the code path the GUI runs as a supervised child process: the only process that
    opens and parses the untrusted disk. It reports structured progress on stdout and exits
    with a code the parent classifies. It never raises out to the caller -- any failure
    becomes a `fatal` event and a non-zero exit, so a crash is the OS killing this process,
    not an unhandled exception."""
    import faulthandler
    import platform
    import traceback
    from . import __version__, ntfs, worker

    em = worker.Emitter(jsonl=args.jsonl)
    dest = args.recover_files
    # Reader stats power the diagnostic log; turn them on for the whole run (the flag is read
    # when each reader is constructed, so setting it here, before find_ntfs_volume, is enough).
    ntfs._READER_STATS = True
    ntfs._READER_STATS_TOTAL = {"readers": 0, "reads": 0, "max_len": 0, "max_off": 0,
                                "rejected": 0, "hist": {}}
    os.makedirs(dest, exist_ok=True)
    diag = worker.DiagLog(worker.diag_path(dest), verbose=args.debug)
    if diag.file is not None:
        # A native/OS-level death now leaves its traceback in the diagnostic file too.
        faulthandler.enable(file=diag.file, all_threads=True)
    diag.section("ScanCrypt recovery diagnostic")
    diag.kv(version=__version__, platform=platform.platform(),
            python=platform.python_version(),
            disk=worker.redact_disk_name(args.path),
            disk_size=_safe_size(args.path), verbose=args.debug)

    if not ntfs.available():
        em.emit("fatal", code="NTFS_UNAVAILABLE", message="dissect.ntfs not installed")
        diag.line("FATAL: dissect.ntfs not installed"); diag.close()
        if not args.jsonl:
            print("NTFS support needs dissect.ntfs: pip install \"rprt[ntfs]\"", file=sys.stderr)
        return worker.EXIT_FATAL

    try:
        method = ntfs.disk_read_method(args.path)
        diag.kv(reader=method)
        geo = ntfs.disk_geometry(args.path)
        if geo:
            diag.kv(**{f"geometry_{k}": v for k, v in geo.items()})
        em.emit("started", reader=method, dest=os.path.basename(dest))
        em.emit("phase", name="locate_volume")
        diag.section("locate volume")
        base = ntfs.find_ntfs_volume(args.path)
        diag.kv(volume_base=base)
        if base is None:
            em.emit("fatal", code="NO_VOLUME",
                    message="no readable NTFS volume (encryption likely reached the block "
                            "map or the volume start)")
            diag.line("NO_VOLUME: no mountable NTFS volume found")
            diag.close()
            if not args.jsonl:
                print("no readable NTFS volume found in this disk", file=sys.stderr)
            return worker.EXIT_NO_VOLUME

        only = None
        if args.only_paths:
            try:
                with open(args.only_paths, encoding="utf-8") as f:
                    only = [ln.rstrip("\n") for ln in f if ln.strip()]
                diag.kv(only_paths=len(only))
            except OSError as exc:
                em.emit("fatal", code="ERROR", message=f"could not read --only-paths: {exc}")
                diag.close()
                return worker.EXIT_FATAL

        em.emit("phase", name="extract", base=base)
        diag.section("extract")
        counters = {"ok": 0, "failed": 0, "bytes": 0, "warned": 0}

        def on_file(r):
            rel = r.get("path", "")
            if "error" in r:
                counters["failed"] += 1
                em.emit("warning", code="FILE_FAILED", path=rel, message=r["error"])
                # Cap warning volume in the log; paths only in verbose mode.
                if counters["warned"] < 500:
                    counters["warned"] += 1
                    diag.line(f"WARN {r['error']}" + (f"  {rel}" if args.debug else ""))
            else:
                counters["ok"] += 1
                counters["bytes"] += r.get("written", 0)
                em.emit("file_recovered", path=rel, bytes_written=r.get("written", 0))
                if args.debug:
                    diag.line(f"OK {r.get('written', 0):>14,}  {rel}")

        _tty = sys.stderr is not None and sys.stderr.isatty()
        _pk = {"k": None}

        def progress(frac, label):
            em.emit("progress", fraction=round(frac, 4), files_recovered=counters["ok"],
                    bytes_written=counters["bytes"])
            if args.jsonl or sys.stderr is None:
                return
            pct = frac * 100
            if _tty:                                  # overwrite one line, throttled to 0.1%
                key = (label, round(pct, 1))
                if key == _pk["k"]:
                    return
                _pk["k"] = key
                print(f"\r{label}: {pct:5.1f}%", end="", file=sys.stderr, flush=True)
            else:                                     # log: one newline-terminated line per 5%
                key = (label, int(pct // 5))
                if key == _pk["k"]:
                    return
                _pk["k"] = key
                print(f"{label}: {pct:.0f}%", file=sys.stderr, flush=True)

        if only is not None:
            # Direct path lookup per selected file -- near-instant, no full-MFT walk.
            ntfs.extract_selected(args.path, base, dest, only,
                                  progress=progress, on_file=on_file)
        else:
            ntfs.extract_all(args.path, base, dest, min_size=args.min_file_size,
                             progress=progress, on_file=on_file)
        # Full recovery only: flag if MFT holes mean some files could not be listed at all.
        coverage = None
        if only is None:
            try:
                with ntfs.MountedNTFS(args.path, base) as _m:
                    coverage = ntfs.mft_coverage(_m.fs)
            except Exception:  # noqa: BLE001 -- coverage is advisory, never fatal
                coverage = None
        missing = (coverage or {}).get("missing_in_range", 0)
        summary = {"files_recovered": counters["ok"], "files_failed": counters["failed"],
                   "bytes_written": counters["bytes"], "reader": method, "base": base,
                   "partial": bool(missing), "mft_missing_records": missing,
                   "reader_stats": ntfs.reader_stats()}
        worker.write_summary(dest, summary)
        diag.section("summary")
        diag.kv(files_recovered=counters["ok"], files_failed=counters["failed"],
                bytes_written=counters["bytes"], mft_missing_records=missing,
                reader_stats=ntfs.reader_stats())
        diag.close()
        if missing:
            em.emit("warning", code="PARTIAL_MFT", missing_records=missing,
                    message="recovery is partial: some MFT records were unrecoverable")
        em.emit("completed", **summary)
        if not args.jsonl:
            print(file=sys.stderr)
            if missing:
                print(f"WARNING: recovery is PARTIAL -- {missing:,} MFT record(s) within the "
                      f"used range were unrecoverable (their disk blocks did not survive), so "
                      f"some files could not be recovered.", file=sys.stderr)
            print(f"recovered {counters['ok']:,} file(s), {counters['bytes']:,} bytes to {dest}"
                  f"{' (partial)' if missing else ''}", file=sys.stderr)
            print(f"diagnostic log: {worker.diag_path(dest)}", file=sys.stderr)
        return worker.EXIT_OK
    except KeyboardInterrupt:
        em.emit("fatal", code="CANCELLED", message="cancelled")
        diag.line("CANCELLED"); diag.close()
        return worker.EXIT_CANCELLED
    except Exception as exc:  # noqa: BLE001 -- never propagate; report and exit non-zero
        em.emit("fatal", code="ERROR", message=str(exc))
        diag.section("fatal error")
        diag.line("".join(traceback.format_exc()))
        diag.close()
        if not args.jsonl:
            print(f"recovery failed: {exc}", file=sys.stderr)
        return worker.EXIT_FATAL


def _safe_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _handle_ntfs(args, report, progress):
    from . import ntfs
    if not ntfs.available():
        print("NTFS support needs dissect.ntfs: pip install \"rprt[ntfs]\"", file=sys.stderr)
        return 1
    base = _ntfs_offset_from(args, report)
    if base is None:
        print("no intact NTFS volume found in the recoverable region "
              "(pass --ntfs-offset to force one)", file=sys.stderr)
        return 1
    print(f"NTFS volume at offset {base:,}", file=sys.stderr)

    try:
        if args.list_files:
            with ntfs.MountedNTFS(args.path, base) as m:
                files = ntfs.list_files(m.fs, min_size=args.min_file_size)
            for path, size in sorted(files, key=lambda x: -x[1]):
                print(f"{size/2**20:12,.1f} MB  {path}")
            print(f"{len(files):,} file(s)", file=sys.stderr)

        if args.extract_files:
            results = ntfs.extract_all(args.path, base, args.extract_files,
                                       min_size=args.min_file_size, progress=progress)
            print(file=sys.stderr)
            ok = [r for r in results if "error" not in r]
            failed = [r for r in results if "error" in r]
            total = sum(r["written"] for r in ok)
            print(f"extracted {len(ok):,} file(s), {total:,} bytes to {args.extract_files}",
                  file=sys.stderr)
            if failed:
                print(f"{len(failed)} file(s) failed:", file=sys.stderr)
                for r in failed[:20]:
                    print(f"  {r['path']}: {r['error']}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 -- a bad/partial volume shouldn't crash the CLI
        print(f"could not read NTFS volume at offset {base:,}: {exc}\n"
              f"(the detected boot-sector signature may be a false positive, or the volume "
              f"metadata itself may be inside the encrypted region)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
