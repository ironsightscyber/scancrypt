"""rprt.report: self-contained HTML triage report.

The product wedge is a free "how much of my data can I get back?" number handed to a
victim (and their insurer) before they consider paying a ransom. This renders a scan
into a single standalone .html file -- inline CSS and an inline SVG entropy map, no
external assets -- suitable for emailing or attaching to a claim.

Forensic note: the report can carry the input's SHA-256 so a reader can verify the tool
read the evidence without altering it. Hashing a 100+ GB disk is slow, so it's optional.
"""
from __future__ import annotations

import hashlib
import html
from datetime import datetime
from typing import Optional

from . import __version__
from .engine import ScanReport, ProgressFn
from .source import open_source

# Recoverability drives the headline colour: green = mostly recoverable, amber = mixed,
# red = little/none. These are presentation only; the honest-caveats text always applies.
_GOOD = "#37E28C"   # signal green: mostly recoverable
_WARN = "#F0B03E"   # amber: mixed
_BAD = "#FF5A5A"    # encrypted red: little or nothing recoverable

# ScanCrypt logo mark (scan reticle + red/green entropy bar), inline so the report stays
# self-contained. Matches the site brand.
_SC_MARK = (
    '<svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true" style="flex:none">'
    '<path d="M4 10V5a1 1 0 0 1 1-1h5M22 4h5a1 1 0 0 1 1 1v5M28 22v5a1 1 0 0 1-1 1h-5'
    'M10 28H5a1 1 0 0 1-1-1v-5" fill="none" stroke="#37E28C" stroke-width="2" stroke-linecap="round"/>'
    '<rect x="10" y="14" width="4" height="4" rx="1" fill="#FF5A5A"/>'
    '<rect x="15" y="14" width="8" height="4" rx="1" fill="#37E28C"/></svg>'
)

# Shared report stylesheet: the ScanCrypt "diagnostic instrument" look. Self-contained (no
# web fonts); a system stack stands in for the site's Archivo/IBM Plex. A print override
# flips to light so a report attached to a claim prints cleanly.
_REPORT_CSS = """
  :root{
    --bg:#0A0C11;--panel:#12161f;--panel-2:#161b25;
    --ink:#EDEFF3;--dim:#9AA2B1;--muted:#6b7280;
    --line:rgba(255,255,255,.09);--line-2:rgba(255,255,255,.14);
    --sig:#37E28C;--enc:#FF5A5A;--warn:#F0B03E;--empty:#2a3242;
    --display:"Archivo",system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --body:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{font-family:var(--body);font-size:15px;line-height:1.55;margin:0;padding:2.4rem 2rem;
    color:var(--dim);background:var(--bg)}
  .wrap{max-width:980px;margin:0 auto}
  h1,h2{font-family:var(--display);color:var(--ink);letter-spacing:-.02em}
  h1{font-size:1.55rem;font-weight:800;margin:0 0 .25rem}
  h2{font-size:1.1rem;font-weight:700;margin:1.9rem 0 .5rem}
  .brand{display:flex;align-items:center;gap:10px;margin-bottom:1.5rem;padding-bottom:1.2rem;
    border-bottom:1px solid var(--line)}
  .brand .w{font-family:var(--display);font-weight:800;color:var(--ink);font-size:1.16rem;letter-spacing:-.02em}
  .brand .t{font-family:var(--mono);font-size:.7rem;color:var(--muted);text-transform:uppercase;
    letter-spacing:.1em;margin-left:auto}
  .sub{color:var(--muted);margin:0 0 1.3rem;font-size:.92rem}
  .verdict{font-size:2.1rem;font-weight:800;font-family:var(--display);letter-spacing:-.02em;margin:1rem 0 .3rem;line-height:1.05}
  .verdict small{display:block;font-size:.92rem;font-weight:400;color:var(--dim);
    font-family:var(--body);letter-spacing:0;margin-top:.4rem;max-width:70ch}
  figure{margin:1.5rem 0}
  figcaption{font-size:.8rem;color:var(--muted);margin-top:.5rem;line-height:1.5}
  .legend{margin-top:.7rem}
  .legend span{display:inline-block;margin-right:1.1rem;font-size:.75rem;font-family:var(--mono);color:var(--muted)}
  .sw{display:inline-block;width:.72rem;height:.72rem;vertical-align:middle;margin-right:.35rem;border-radius:2px}
  table{border-collapse:collapse;width:100%;margin:.4rem 0 1.4rem}
  th,td{text-align:left;padding:.5rem .65rem;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--dim);font-weight:600;width:34%;font-size:.9rem}
  td{font-variant-numeric:tabular-nums;word-break:break-word;color:var(--ink)}
  .cols{display:flex;gap:2rem;flex-wrap:wrap}
  .cols>div{flex:1;min-width:240px}
  .scroll{overflow-x:auto}
  .note{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--muted);
    padding:.8rem 1rem;border-radius:4px;margin:1rem 0;font-size:.92rem}
  .warn{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--warn);
    padding:.8rem 1rem;border-radius:4px;font-size:.92rem;color:var(--ink)}
  .caveats{font-size:.9rem;color:var(--dim)}
  .caveats li{margin:.35rem 0}
  .assist{border:1px solid var(--line-2);border-radius:6px;margin:1.7rem 0;padding:20px 24px;
    background:linear-gradient(135deg,rgba(55,226,140,.07),var(--panel))}
  .assist .k{font-family:var(--mono);font-size:.7rem;color:var(--sig);text-transform:uppercase;letter-spacing:.09em;margin-bottom:9px}
  .assist p{margin:0 0 14px;color:var(--ink);font-size:.95rem}
  .assist a.cta{display:inline-block;font-family:var(--mono);font-weight:700;font-size:.85rem;
    background:var(--sig);color:#04120a;padding:.6rem 1.1rem;border-radius:3px;text-decoration:none}
  a{color:var(--sig)}
  footer{margin-top:2.2rem;font-size:.75rem;color:var(--muted);border-top:1px solid var(--line);
    padding-top:1.1rem;font-family:var(--mono);line-height:1.6}
  @media print{
    body{background:#fff;color:#1a1a1a;padding:1rem}
    h1,h2,.brand .w,td{color:#111}
    th{color:#333} .sub,figcaption,.legend span,footer,.brand .t{color:#555}
    .note,.warn{background:#f5f5f5;color:#111}
    .assist{background:#f5f5f5} .assist p{color:#111} .assist a.cta{background:#111;color:#fff}
    th,td,.note,.warn,.brand,footer{border-color:#ccc}
  }
"""


def contact_from_env():
    """Build an optional recovery-assistance contact block from environment variables, so a
    firm can set it once (RPRT_FIRM_NAME, RPRT_FIRM_URL, RPRT_FIRM_BLURB) and have it appear
    in reports from both the CLI and the GUI. Returns None if no firm is configured, which
    keeps the open-source default report neutral."""
    import os
    firm = os.environ.get("RPRT_FIRM_NAME")
    if not firm:
        return None
    return {"firm": firm, "url": os.environ.get("RPRT_FIRM_URL", ""),
            "blurb": os.environ.get("RPRT_FIRM_BLURB", "")}


def _assist_section(contact) -> str:
    """Render the optional 'need this handled?' block. Empty unless a firm is supplied, so
    the default output stays a neutral evidence document rather than an advertisement."""
    if not contact or not contact.get("firm"):
        return ""
    firm = html.escape(str(contact["firm"]))
    blurb = contact.get("blurb") or (
        "ScanCrypt shows what is recoverable. If you would rather have the recovery carried "
        f"out for you, including full extraction, database rebuilds, and forensic reporting, "
        f"{contact['firm']} can help.")
    btn = ""
    if contact.get("url"):
        btn = f'<a class="cta" href="{html.escape(str(contact["url"]))}">Contact {firm} &rarr;</a>'
    return (f'<div class="assist"><div class="k">recovery assistance</div>'
            f'<p>{html.escape(blurb)}</p>{btn}</div>')


# Always-on, discreet attribution for the report footer (credit, not a pitch). No protocol
# in the visible text; scancrypt.org is a plain hyperlink.
_ATTRIBUTION = ('a free and open-source tool by IronSights '
                '(<a href="https://scancrypt.org">scancrypt.org</a>)')


def sha256_of_input(path: str, progress: ProgressFn = None, cancel_check=None,
                    chunk_size: int = 8 * 1024 * 1024) -> str:
    """Stream the whole input through SHA-256. Read-only. Can be cancelled."""
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


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:,.1f} {unit}" if unit != "B" else f"{int(size):,} B"
        size /= 1024
    return f"{size:,.1f} TB"


def _verdict_color(report: ScanReport) -> str:
    pct = report.recoverable_pct
    if report.pattern == "fully-encrypted" or pct < 10:
        return _BAD
    if pct < 90:
        return _WARN
    return _GOOD


# Shared colours for the entropy map, used by both the HTML/SVG report and the Qt widget.
STRIP_BG = "#2a3242"
STRIP_ENCRYPTED = "#FF5A5A"
STRIP_INTACT = "#37E28C"
STRIP_ZERO = "#2a3242"
STRIP_MARKER = "#C3CAD6"


def expected_boundary_fraction(report: ScanReport):
    """If the identified family has a known intended encrypted extent (e.g. Makop's
    ~1/3), return it as a 0..1 fraction so the entropy strip can mark where the encryptor
    *meant* to reach -- usually well past the actual (interrupted) boundary. Returns None
    when there's no family, no known extent, or the mark would sit at/after the file end."""
    fam = report.family
    if not fam:
        return None
    frac = fam.get("typical_max_encrypted_fraction")
    if not frac or frac <= 0 or frac >= 1:
        return None
    return frac


def entropy_segments(report: ScanReport):
    """Compute the coloured segments of the entropy map as (x_frac, w_frac, kind) tuples,
    where kind is 'encrypted' | 'intact' | 'zero'. Fractions are 0..1 across the file.
    Shared by the SVG report and the GUI widget so both draw an identical picture."""
    segments = []
    size = max(report.size, 1)

    if report.coarse_samples:
        rows = report.coarse_samples
        n = len(rows)
        for i, (off, _ent, cls) in enumerate(rows):
            x0 = off / size
            x1 = rows[i + 1][0] / size if i + 1 < n else 1.0
            kind = cls if cls in ("encrypted", "intact", "zero") else "intact"
            segments.append((x0, max(x1 - x0, 0.0), kind))
    elif report.boundary_offset is not None:
        b = report.boundary_offset / size
        segments.append((0.0, b, "encrypted"))
        segments.append((b, 1.0 - b, "intact"))
    elif report.run_length_sample and report.block_size:
        bs = report.block_size
        segments.append((0.0, 1.0, "intact"))
        for start_blk, length in report.run_length_sample:
            segments.append((start_blk * bs / size, max(length * bs / size, 0.001), "encrypted"))
    return segments


def _entropy_strip_svg(report: ScanReport, width: int = 900, height: int = 54) -> str:
    """Horizontal band across the file, coloured by what each region reads as. Purely
    illustrative -- exact offsets are in the table below the figure."""
    colors = {"encrypted": STRIP_ENCRYPTED, "intact": STRIP_INTACT, "zero": STRIP_ZERO}
    rects = [f'<rect x="0" y="0" width="{width}" height="{height}" fill="{STRIP_BG}"/>']
    for x_frac, w_frac, kind in entropy_segments(report):
        x = round(x_frac * width, 2)
        w = max(round(w_frac * width, 2), 0.5)
        rects.append(f'<rect x="{x}" y="0" width="{w}" height="{height}" '
                     f'fill="{colors[kind]}"/>')
    rects.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="none" '
                 f'stroke="#3a4560" stroke-width="1"/>')
    marker = expected_boundary_fraction(report)
    if marker is not None:
        mx = round(marker * width, 2)
        rects.append(f'<line x1="{mx}" y1="0" x2="{mx}" y2="{height}" '
                     f'stroke="{STRIP_MARKER}" stroke-width="1.5" stroke-dasharray="4,3"/>')
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" '
            f'preserveAspectRatio="none" role="img" '
            f'aria-label="Entropy map across the file">{"".join(rects)}</svg>')


def _rows_html(pairs) -> str:
    out = []
    for label, value in pairs:
        if value is None:
            continue
        out.append(f"<tr><th>{html.escape(str(label))}</th>"
                   f"<td>{html.escape(str(value))}</td></tr>")
    return "".join(out)


def build_html_report(path: str, report: ScanReport, sha256: Optional[str] = None,
                      scan_params: Optional[dict] = None,
                      generated_at: Optional[datetime] = None,
                      display_name: Optional[str] = None,
                      case: Optional[dict] = None,
                      contact: Optional[dict] = None) -> str:
    """Render a scan into a standalone HTML document string."""
    when = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    name = display_name or path
    color = _verdict_color(report)
    assist_section = _assist_section(contact)

    case_section = ""
    if case and any(case.values()):
        case_rows = _rows_html([
            ("Case ID", case.get("case_id") or None),
            ("Examiner", case.get("examiner") or None),
            ("Evidence ID", case.get("evidence_id") or None),
            ("Description", case.get("description") or None),
            ("Organization", case.get("organization") or None),
        ])
        if case_rows:
            case_section = f"<h2>Case</h2><table>{case_rows}</table>"

    fam = report.family
    if fam:
        conf = ("confirmed" if fam.get("provenance") == "validated"
                else "likely, from public threat reporting, not verified against a sample")
        fam_line = f"{fam['family']} ({conf}; matched on {', '.join(fam['matched_on'])})"
    else:
        fam_line = "Not matched to a known family"

    isolated = report.isolated_high_entropy_offsets
    isolated_note = ""
    if isolated:
        shown = ", ".join(f"{o:,}" for o in isolated[:8])
        more = f" (+{len(isolated) - 8} more)" if len(isolated) > 8 else ""
        isolated_note = (
            f"<p class='warn'><strong>{len(isolated)} isolated high-entropy region(s)</strong> "
            f"exist away from the main boundary, at byte offsets: {shown}{more}. These did not "
            f"affect the recoverable estimate but should be verified with a format-aware check "
            f"before being treated as intact.</p>"
        )

    identity_rows = _rows_html([
        ("Input", name),
        ("Size", f"{_human_bytes(report.size)} ({report.size:,} bytes)"),
        ("SHA-256 (input, read-only)", sha256 or "not computed"),
        ("Ransomware family", fam_line),
    ])

    finding_rows = _rows_html([
        ("Recoverable", f"{report.recoverable_pct:.2f}%, {_human_bytes(report.recoverable_bytes)}"),
        ("Encrypted", f"{report.encrypted_pct:.4f}%, {_human_bytes(report.encrypted_bytes)}"),
        ("Pattern", report.pattern),
        ("Scan mode", report.mode),
        ("Boundary offset", f"{report.boundary_offset:,} bytes" if report.boundary_offset is not None else None),
        ("Block size", f"{report.block_size:,} bytes" if report.block_size else None),
        ("High-entropy blocks", f"{report.high_entropy_blocks:,} of {report.total_blocks:,}"
         if report.total_blocks is not None else None),
        ("High-entropy runs", report.runs),
    ])

    param_rows = ""
    if scan_params:
        param_rows = _rows_html(list(scan_params.items()))

    formats_section = ""
    if report.formats:
        rows = "".join(
            f"<tr><th>{html.escape(f['name'])}</th><td>at offset {f['offset']:,} "
            f"({html.escape(f['where'])})<br><span style='color:#6b7280'>"
            f"{html.escape(f['extraction_hint'])}</span></td></tr>"
            for f in report.formats
        )
        formats_section = (
            "<h2>Recoverable content detected</h2>"
            "<p class='sub'>Formats/filesystems found in the intact region, recover these "
            "with a structure-aware step rather than a blind byte carve.</p>"
            f"<table>{rows}</table>"
        )

    marker_frac = expected_boundary_fraction(report)
    marker_legend = ""
    marker_caption = ""
    if marker_frac is not None and fam:
        marker_legend = (
            '<span><i class="sw" style="background:transparent;'
            'border-left:2px dashed #C3CAD6;width:0"></i>'
            f'family\'s intended encrypted extent (~{marker_frac*100:.0f}%)</span>'
        )
        marker_caption = (
            f" The dashed line marks how far {html.escape(fam['family'])} typically "
            f"intends to encrypt (~{marker_frac*100:.0f}%); the actual encrypted region "
            "usually falls well short because the encryptor is interrupted."
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanCrypt Triage Report</title>
<style>{_REPORT_CSS}</style></head>
<body><div class="wrap">
  <div class="brand">{_SC_MARK}<span class="w">ScanCrypt</span><span class="t">triage report</span></div>
  <h1>Partial-recovery triage</h1>
  <p class="sub">Ransomware-aware recoverability assessment · generated {html.escape(when)}</p>

  <div class="verdict" style="color:{color}">{report.recoverable_pct:.2f}% recoverable
    <small>{_human_bytes(report.recoverable_bytes)} of {_human_bytes(report.size)},
    recovered without a decryption key by reading back the bytes that were never encrypted.</small>
  </div>

  <figure>
    {_entropy_strip_svg(report)}
    <figcaption>Entropy map across the file (left = start). Exact offsets in the table below.{marker_caption}</figcaption>
    <div class="legend">
      <span><i class="sw" style="background:var(--enc)"></i>encrypted</span>
      <span><i class="sw" style="background:var(--sig)"></i>intact / recoverable</span>
      <span><i class="sw" style="background:var(--empty)"></i>empty (unallocated)</span>
      {marker_legend}
    </div>
  </figure>

  {case_section}

  <h2>Identification</h2>
  <table>{identity_rows}</table>

  <h2>Findings</h2>
  <table>{finding_rows}</table>
  <div class="note">{html.escape(report.note)}</div>
  {isolated_note}

  {formats_section}

  {"<h2>Scan parameters</h2><table>" + param_rows + "</table>" if param_rows else ""}

  <h2>How to read this, and its limits</h2>
  <ul class="caveats">
    <li>This is <strong>not decryption</strong>. It recovers the portion of the file the
        ransomware never encrypted; the encrypted portion remains unrecoverable without the key.</li>
    <li>Recoverability is <strong>"most, not all"</strong>. The figure above is the measured
        percentage, never a guarantee of a clean, usable file.</li>
    <li>Small files are usually fully encrypted; this technique helps with large files
        (databases, VM disks, backup archives, large media).</li>
    <li>Structured files (databases, archives) may need format-aware reassembly even when the
        underlying bytes survive; fragmentation can still defeat a clean rebuild.</li>
    <li>The input was opened <strong>read-only</strong> and never modified.</li>
  </ul>

  {assist_section}

  <footer>Generated by ScanCrypt v{html.escape(__version__)}, {_ATTRIBUTION}. rprt.report ·
    entropy threshold and pattern classification are heuristic and should be corroborated
    for high-stakes recovery decisions.</footer>
</div></body></html>"""


def write_html_report(path: str, report: ScanReport, out_path: str, **kwargs) -> str:
    """Build and write the report to out_path. Returns out_path."""
    doc = build_html_report(path, report, **kwargs)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


# ---------------------------------------------------------------- incident-level report

_RECOVERABLE_PATTERNS = {"fully-intact", "front-only", "scattered-benign",
                         "compressed-benign", "mixed", "non-contiguous"}


def build_incident_report(result, generated_at: Optional[datetime] = None,
                          top_n: int = 200, contact: Optional[dict] = None) -> str:
    """Render an incident-wide batch result into a standalone HTML report: the headline
    recoverable fraction across the whole share, breakdowns by pattern and family, and a
    (capped) per-file table sorted by recoverable bytes. `result` is a batch.BatchResult."""
    when = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    assist_section = _assist_section(contact)
    pct = result.recoverable_pct
    color = _GOOD if pct >= 60 else (_WARN if pct >= 20 else _BAD)

    strain = result.identified_strain()
    note_fams = result.note_families()
    strain_line = ""
    if strain:
        via = "ransom note" if note_fams else "encrypted-file signatures"
        strain_line = (f"<p class='sub'><strong>Ransomware strain:</strong> "
                       f"{html.escape(strain)}, identified via {via}"
                       f" ({len(result.notes)} ransom note(s) found).</p>")

    def _brk_rows(d, fmt=lambda v: v):
        return "".join(f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(fmt(v)))}</td></tr>"
                       for k, v in d.items()) or "<tr><td colspan='2'>none</td></tr>"

    bytes_by_pattern = result.bytes_by_pattern()
    fam = result.family_breakdown()

    files_sorted = sorted(result.files, key=lambda f: -f.recoverable_bytes)[:top_n]
    file_rows = "".join(
        f"<tr><td>{html.escape(fr.path)}</td>"
        f"<td>{_human_bytes(fr.size)}</td>"
        f"<td>{html.escape(fr.pattern or '(error)')}</td>"
        f"<td>{fr.recoverable_pct:.1f}%</td>"
        f"<td>{html.escape(fr.family or '')}</td></tr>"
        for fr in files_sorted
    )
    capped = ("" if len(result.files) <= top_n else
              f"<p class='sub'>Showing the top {top_n} of {len(result.files):,} files by "
              f"recoverable bytes; the CSV export lists them all.</p>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanCrypt Incident Report</title>
<style>{_REPORT_CSS}
  th {{ width:auto; }}
</style></head>
<body><div class="wrap">
  <div class="brand">{_SC_MARK}<span class="w">ScanCrypt</span><span class="t">incident report</span></div>
  <h1>Incident recovery triage</h1>
  <p class="sub">{html.escape(result.root)} &middot; generated {html.escape(when)}</p>
  {strain_line}

  <div class="verdict" style="color:{color}">{pct:.1f}% recoverable
    <small>{_human_bytes(result.recoverable_bytes)} of {_human_bytes(result.total_bytes)}
    across {result.scanned:,} scanned file(s), recoverable for free, without a decryption
    key, by reading back the bytes that were never encrypted.</small>
  </div>

  <div class="cols">
    <div><h2>By outcome (files)</h2><table>{_brk_rows(result.pattern_breakdown())}</table></div>
    <div><h2>By outcome (bytes)</h2><table>{_brk_rows(bytes_by_pattern, _human_bytes)}</table></div>
    <div><h2>Ransomware families</h2><table>{_brk_rows(fam)}</table></div>
  </div>

  <h2>Files by recoverable size</h2>
  {capped}
  <div class="scroll"><table>
    <tr><th>Path</th><th>Size</th><th>Pattern</th><th>Recoverable</th><th>Family</th></tr>
    {file_rows}
  </table></div>

  <h2>How to read this, and its limits</h2>
  <ul class="caveats">
    <li>This is <strong>not decryption</strong>. It recovers the bytes the ransomware
        never encrypted. The encrypted portion stays unrecoverable without the key.</li>
    <li>The headline is a measured aggregate, <strong>"most, not all"</strong>, never a
        guarantee that every recovered file opens cleanly.</li>
    <li>Small files are usually fully encrypted; the recoverable bytes concentrate in large
        files (databases, VM disks, backups, media).</li>
    <li>Every file was opened <strong>read-only</strong> and never modified.</li>
  </ul>

  {assist_section}

  <footer>Generated by ScanCrypt v{html.escape(__version__)}, {_ATTRIBUTION}. rprt.batch ·
    scanned {result.scanned:,}, skipped {result.skipped:,}, errors {result.errors:,}.</footer>
</div></body></html>"""


def write_incident_report(result, out_path: str, **kwargs) -> str:
    doc = build_incident_report(result, **kwargs)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
