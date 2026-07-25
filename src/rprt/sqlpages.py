"""rprt.sqlpages — page-level validation of a recovered SQL Server data file (.mdf/.ndf).

After the intact bytes of a database are recovered, this answers "how good is the
recovery?" at the format level -- a structural analogue to DBCC CHECKDB. SQL Server data
files are fixed 8192-byte pages; each page header carries a version byte, a type byte, a
file-id, and the page's own logical page-ID (uint32 at offset 32). On an intact,
unfragmented file every page's page-ID equals its offset (offset / 8192), which is a
strong format-aware validity signal beyond raw entropy.

It also separates genuine encryption from ordinary dense in-row content (LOB/text-in-row,
images): real intermittent encryption makes DENSE, CONSISTENT-length runs of bad pages at
REGULAR spacing; benign binary content makes SHORT runs at IRREGULAR spacing. This is the
check that confirmed a real 2.14 GB production MDF was intact (thousands of 1-7 page runs
at irregular gaps = benign LOB data, later confirmed by a clean DBCC CHECKDB).

Read-only, and reads through rprt.source so it works on files, images, and raw devices.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .source import open_source

try:
    import numpy as _np
except ImportError:
    _np = None

PAGE_SIZE = 8192
VALID_PAGE_TYPES = {1, 2, 3, 4, 7, 8, 9, 10, 11, 13, 15, 16, 17, 18, 19, 20}
PAGE_TYPE_NAMES = {
    1: "data", 2: "index", 3: "textmix", 4: "texttree", 7: "sort", 8: "GAM", 9: "SGAM",
    10: "IAM", 11: "PFS", 13: "boot", 15: "fileheader", 16: "diffmap", 17: "MLmap",
}
READ_CHUNK_PAGES = 512   # pages per sequential read (4 MiB)

ProgressFn = Optional[Callable[[float, str], None]]


@dataclass
class SqlValidation:
    size: int
    total_pages: int
    pages_checked: int
    valid_pages: int
    free_space_pages: int
    anomalous_pages: int
    valid_pct: float
    page_shift: int = 0
    page_type_distribution: dict = field(default_factory=dict)
    anomalous_runs: int = 0
    anomalous_run_sample: list = field(default_factory=list)
    verdict: str = ""
    verdict_note: str = ""
    database_name_guess: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "page_size": PAGE_SIZE,
            "total_pages": self.total_pages,
            "pages_checked": self.pages_checked,
            "valid_pages": self.valid_pages,
            "free_space_pages": self.free_space_pages,
            "anomalous_pages": self.anomalous_pages,
            "valid_pct": self.valid_pct,
            "page_shift": self.page_shift,
            "page_type_distribution": self.page_type_distribution,
            "anomalous_runs": self.anomalous_runs,
            "anomalous_run_sample": self.anomalous_run_sample,
            "verdict": self.verdict,
            "verdict_note": self.verdict_note,
            "database_name_guess": self.database_name_guess,
        }


_UNSHIFTED = frozenset({0})


def check_page_header(page: bytes, page_index: int, shifts=_UNSHIFTED):
    """Returns (is_valid_header, page_type_name_or_None, page_is_in_place). `shifts` is the set
    of page-ID offsets the file uses: a page belongs where its stored ID says it does, so it is
    "in place" when (page_id - index) is one of them. {0} for an ordinary file laid out at its
    own offsets; a recovered/carved MDF sits behind a prefix (one shift) or is fragmented into
    several extents (several shifts). A lone mismatch is not in the set, so it stays anomalous."""
    if len(page) < 40:
        return False, None, False
    header_version = page[0]
    page_type = page[1]
    page_id = int.from_bytes(page[32:36], "little")
    file_id = int.from_bytes(page[36:38], "little")
    valid = header_version == 1 and file_id == 1 and page_type in VALID_PAGE_TYPES
    return valid, PAGE_TYPE_NAMES.get(page_type), ((page_id - page_index) in shifts)


def detect_page_shifts(src, total_pages: int) -> dict:
    """A recovered/carved MDF is frequently offset by a fixed number of pages (a prefix before
    logical page 0), so page_id == physical_index + shift; a fragmented one carries several such
    offsets, one per extent. Sample valid-header pages and return {shift: sample_count} for the
    shifts that recur enough to be real extents (a shift seen once or twice is a stray
    misplaced/corrupt page and is deliberately left out, so it stays anomalous). Without this a
    perfectly recoverable but shifted database validates as 0% intact -- every page looks
    'misplaced' against the naive page_id == index assumption."""
    from collections import Counter

    if total_pages <= 0:
        return {}
    shifts = Counter()
    step = max(total_pages // 2048, 1)
    for idx in range(0, total_pages, step):
        page = src.read_at(idx * PAGE_SIZE, PAGE_SIZE)
        if len(page) < 40 or page[0] != 1 or page[1] not in VALID_PAGE_TYPES:
            continue
        if int.from_bytes(page[36:38], "little") != 1:          # file_id must be 1
            continue
        shifts[int.from_bytes(page[32:36], "little") - idx] += 1
    if not shifts:
        return {}
    # A valid SQL header is near-impossible in random data, so any recurring shift is a real
    # extent. Keep shifts seen at least a few times (and above a small fraction of the samples);
    # drop the ones seen once or twice as stray corruption.
    floor = max(3, sum(shifts.values()) // 100)
    return {s: n for s, n in shifts.items() if n >= floor}


def read_boot_page_db_name(src):
    """SQL Server's boot page (logical page 9) holds the database name as UTF-16LE. A
    cheap, high-confidence sanity check that this is the file you think it is."""
    boot = src.read_at(9 * PAGE_SIZE, PAGE_SIZE)
    if len(boot) < PAGE_SIZE:
        return []
    text = boot.decode("utf-16-le", errors="ignore")
    return re.findall(r"[ -~]{4,}", text)[:5]


def _classify_page_chunk(data: bytes, base_index: int, sample_every: int, shifts=_UNSHIFTED):
    """Classify each page in a chunk. Returns (good_type_names, zero_count, anomalous_indices).
    Vectorised with numpy when available; the chunk holds pages base_index, base_index+step,...
    `shifts` is the file's detected set of page-ID offsets (see detect_page_shifts)."""
    n = len(data) // PAGE_SIZE
    if n == 0:
        return [], 0, []
    if _np is None:
        good, zero, anom = [], 0, []
        for j in range(n):
            page = data[j * PAGE_SIZE:(j + 1) * PAGE_SIZE]
            idx = base_index + j * sample_every
            valid, ptype, id_match = check_page_header(page, idx, shifts)
            if valid and id_match:
                good.append(ptype)
            elif page.count(0) == len(page):
                zero += 1
            else:
                anom.append(idx)
        return good, zero, anom

    arr = _np.frombuffer(data, dtype=_np.uint8)[:n * PAGE_SIZE].reshape(n, PAGE_SIZE)
    hv = arr[:, 0]
    pt = arr[:, 1]
    page_id = arr[:, 32:36].view("<u4").reshape(n).astype(_np.int64)
    file_id = arr[:, 36:38].view("<u2").reshape(n)
    indices = base_index + _np.arange(n, dtype=_np.int64) * sample_every
    valid_type = _np.isin(pt, list(VALID_PAGE_TYPES))
    valid = (hv == 1) & (file_id == 1) & valid_type
    id_match = _np.isin(page_id - indices, list(shifts))
    is_good = valid & id_match
    is_zero = ~arr.any(axis=1)
    is_anom = ~is_good & ~is_zero

    good_types = [PAGE_TYPE_NAMES.get(int(t)) for t in pt[is_good]]
    zero = int(is_zero.sum())
    anom = indices[is_anom].tolist()
    return good_types, zero, anom


def validate(path: str, sample_every: int = 1, progress: ProgressFn = None,
             cancel_check=None) -> SqlValidation:
    """Validate every (or every Nth) page of a recovered MDF/NDF. Read-only."""
    from collections import Counter

    with open_source(path) as src:
        size = src.size
        total_pages = size // PAGE_SIZE
        good = zero = 0
        type_counts = Counter()
        anom_indices = []
        db_name = read_boot_page_db_name(src)
        # A recovered MDF may sit at a page-ID offset (or several, if fragmented); detect them so
        # shifted-but-intact pages count as recoverable instead of validating as 0%.
        shift_counts = detect_page_shifts(src, total_pages)
        shifts = frozenset(shift_counts) or _UNSHIFTED
        dominant_shift = max(shift_counts, key=shift_counts.get) if shift_counts else 0

        step = max(sample_every, 1)
        pages_per_read = max(READ_CHUNK_PAGES, step) // step * step or step
        page = 0
        while page < total_pages:
            if cancel_check is not None and cancel_check():
                break
            if progress:
                progress(page / max(total_pages, 1), "Validating pages")
            if step == 1:
                want = min(pages_per_read, total_pages - page)
                data = src.read_at(page * PAGE_SIZE, want * PAGE_SIZE)
                gtypes, z, anom = _classify_page_chunk(data, page, 1, shifts)
                good += len(gtypes)
                zero += z
                type_counts.update(gtypes)
                anom_indices.extend(anom)
                page += want
            else:
                # sampled: read one page every `step` pages
                p = src.read_at(page * PAGE_SIZE, PAGE_SIZE)
                if len(p) < PAGE_SIZE:
                    break
                valid, ptype, id_match = check_page_header(p, page, shifts)
                if valid and id_match:
                    good += 1
                    type_counts[ptype] += 1
                elif p.count(0) == len(p):
                    zero += 1
                else:
                    anom_indices.append(page)
                page += step

    checked = good + zero + len(anom_indices)
    runs = _to_runs(anom_indices, step)
    verdict, note = _classify(runs, total_pages, good)
    # State the recover/triage facts separately from the encryption verdict, so free space can't
    # read as damage: how much intact SQL is present, and its layout (offsets are neutral, not
    # "fragmentation"). True usability is decided by attaching the file, not by a page percentage.
    if good:
        note += f" {good:,} intact SQL Server page(s) present"
        top = ", ".join(f"{t} ×{c:,}" for t, c in type_counts.most_common(4) if t)
        if top:
            note += f" ({top})"
        note += "."
        if dominant_shift:
            regions = len(shift_counts)
            note += (f" Pages carry a page-ID offset of {dominant_shift:,}"
                     + (f" ({regions} offset regions)." if regions > 1 else "."))

    if progress:
        progress(1.0, "Done")

    return SqlValidation(
        size=size, total_pages=total_pages, pages_checked=checked,
        valid_pages=good, free_space_pages=zero, anomalous_pages=len(anom_indices),
        valid_pct=round(100 * good / max(checked, 1), 2), page_shift=dominant_shift,
        page_type_distribution=dict(type_counts.most_common()),
        anomalous_runs=len(runs), anomalous_run_sample=runs[:10],
        verdict=verdict, verdict_note=note,
        database_name_guess=db_name,
    )


def _to_runs(indices, step):
    if not indices:
        return []
    runs = []
    start = prev = indices[0]
    for idx in indices[1:]:
        if idx != prev + step:
            runs.append((start, (prev - start) // step + 1))
            start = idx
        prev = idx
    runs.append((start, (prev - start) // step + 1))
    return runs


def _classify(runs, total_pages, valid_pages):
    """Verdict about the *encryption threat* to a recovered SQL Server file -- not a measure of
    how intact the database is. A low share of valid pages is normally free space: unallocated
    pages hold old deleted content that passes no page-header check, so most of a large-but-empty
    MDF looks 'anomalous' without being damaged. So this reports the encryption pattern (if any);
    how much intact SQL data is present is stated separately by the caller."""
    if not runs:
        if valid_pages == 0:
            return "no-sql-data", "No SQL Server pages, and no anomalies -- empty or all free space."
        return "clean", "No anomalous pages; the SQL Server pages present are structurally intact."

    lengths = [r[1] for r in runs]
    starts = [r[0] for r in runs]
    gaps = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)] if len(starts) > 1 else []

    if len(runs) == 1 and lengths[0] > total_pages * 0.05:
        return ("likely-encrypted",
                f"A single contiguous run of {lengths[0]:,} non-SQL pages "
                f"({100*lengths[0]/max(total_pages,1):.2f}% of the file) -- consistent with a "
                f"front/contiguous encrypted region (confirm with a per-page entropy check).")

    avg_len = sum(lengths) / len(lengths)
    avg_gap = (sum(gaps) / len(gaps)) if gaps else 0
    len_spread = (max(lengths) - min(lengths)) if lengths else 0
    gap_spread = (max(gaps) - min(gaps)) if gaps else 0

    if gaps and avg_gap > 0 and (len_spread / max(avg_len, 1)) < 0.3 and (gap_spread / avg_gap) < 0.3:
        return ("possibly-intermittent-encryption",
                f"{len(runs)} runs of consistent length (avg {avg_len:.1f} pages) at "
                f"consistent spacing (avg {avg_gap:.1f} pages apart) -- this regularity is "
                f"the signature of deliberate intermittent encryption, not ordinary content. "
                f"Treat this file as likely still partially encrypted.")

    return ("sql-data-present",
            f"{len(runs)} short, irregularly-spaced non-SQL runs (avg {avg_len:.1f} pages) -- "
            f"free space / non-database content (unallocated pages holding old data), which is "
            f"normal in a large MDF and not a sign of encryption or damage.")
