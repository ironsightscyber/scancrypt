"""Page-level SQL MDF validation.

Unlike NTFS, SQL Server pages are simple enough to synthesise exactly: 8192-byte pages
with header byte 0 = version, byte 1 = type, uint32 at 32 = page-id, uint16 at 36 =
file-id. So valid / free / anomalous / encrypted cases are all directly constructible.
"""
import random
import struct

from rprt import sqlpages

PS = sqlpages.PAGE_SIZE


def _valid_page(page_index, ptype=1, fill=b"", page_id=None):
    page = bytearray(PS)
    page[0] = 1                                   # header version
    page[1] = ptype                               # page type (1 = data)
    struct.pack_into("<I", page, 32, page_index if page_id is None else page_id)  # page id
    struct.pack_into("<H", page, 36, 1)           # file id
    body = (fill or b"row data ") * 20
    page[40:40 + len(body)] = body[:PS - 40]
    return bytes(page)


def _zero_page():
    return b"\x00" * PS


def _encrypted_page(seed):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(PS))


def _write(tmp_path, pages, name="db.mdf"):
    p = tmp_path / name
    p.write_bytes(b"".join(pages))
    return str(p)


def test_all_valid_pages_report_clean(tmp_path):
    path = _write(tmp_path, [_valid_page(i) for i in range(64)])
    r = sqlpages.validate(path)
    assert r.total_pages == 64
    assert r.valid_pages == 64
    assert r.anomalous_pages == 0
    assert r.valid_pct == 100.0
    assert r.verdict == "clean"


def test_zero_pages_counted_as_free_space(tmp_path):
    pages = [_valid_page(i) for i in range(30)] + [_zero_page() for _ in range(30, 60)]
    path = _write(tmp_path, pages)
    r = sqlpages.validate(path)
    assert r.valid_pages == 30
    assert r.free_space_pages == 30
    assert r.anomalous_pages == 0
    assert r.verdict == "clean"


def test_front_encrypted_region_flagged(tmp_path):
    # first 20 pages encrypted (contiguous), rest valid -> a single large run
    pages = [_encrypted_page(i) for i in range(20)] + [_valid_page(i) for i in range(20, 200)]
    path = _write(tmp_path, pages)
    r = sqlpages.validate(path)
    assert r.anomalous_pages == 20
    assert r.verdict == "likely-encrypted"


def test_scattered_benign_content_not_flagged_as_encryption(tmp_path):
    # short, irregular runs of high-entropy pages among valid ones = benign LOB content
    rng = random.Random(1)
    pages = []
    i = 0
    while i < 400:
        if rng.random() < 0.06:
            for _ in range(rng.randint(1, 3)):
                pages.append(_encrypted_page(1000 + i)); i += 1
        else:
            pages.append(_valid_page(i)); i += 1
    path = _write(tmp_path, pages[:400])
    r = sqlpages.validate(path)
    assert r.anomalous_pages > 0
    assert r.verdict == "sql-data-present"       # data present; the irregular runs are benign


def test_periodic_encryption_flagged(tmp_path):
    # regular-size runs at regular spacing = intermittent encryption signature
    pages = []
    i = 0
    while i < 300:
        if i % 10 == 0:
            for _ in range(2):
                pages.append(_encrypted_page(500 + i)); i += 1
        else:
            pages.append(_valid_page(i)); i += 1
    path = _write(tmp_path, pages[:300])
    r = sqlpages.validate(path)
    assert r.verdict == "possibly-intermittent-encryption"


def test_uniformly_shifted_file_is_recoverable(tmp_path):
    # a recovered MDF whose pages sit behind a prefix: page_id == physical_index + a constant.
    # Before shift detection this validated as 0% (every page looked misplaced).
    SHIFT = 100000
    pages = [_valid_page(i, page_id=i + SHIFT) for i in range(80)]
    path = _write(tmp_path, pages)
    r = sqlpages.validate(path)
    assert r.valid_pages == 80
    assert r.valid_pct == 100.0
    assert r.page_shift == SHIFT
    assert r.verdict == "clean"


def test_fragmented_file_counts_all_extents(tmp_path):
    # two extents, each with its own consistent page-id shift (a fragmented recovery)
    ext1 = [_valid_page(i, page_id=i + 5000) for i in range(40)]
    ext2 = [_valid_page(i, page_id=i + 900000) for i in range(40, 80)]
    path = _write(tmp_path, ext1 + ext2)
    r = sqlpages.validate(path)
    assert r.valid_pages == 80            # both extents recognised, not written off as anomalous
    assert r.anomalous_pages == 0


def test_page_id_mismatch_is_anomalous(tmp_path):
    # a page with a valid header but wrong page-id (fragmentation/misplacement)
    pages = [_valid_page(i) for i in range(50)]
    bad = bytearray(pages[25]); struct.pack_into("<I", bad, 32, 9999); pages[25] = bytes(bad)
    path = _write(tmp_path, pages)
    r = sqlpages.validate(path)
    assert r.anomalous_pages == 1


def test_sampling_matches_full_scan_verdict(tmp_path):
    pages = [_valid_page(i) for i in range(500)]
    path = _write(tmp_path, pages)
    full = sqlpages.validate(path, sample_every=1)
    sampled = sqlpages.validate(path, sample_every=25)
    assert full.verdict == sampled.verdict == "clean"
    assert sampled.pages_checked < full.pages_checked


def test_vectorised_matches_scalar(tmp_path, monkeypatch):
    pages = ([_valid_page(i) for i in range(40)]
             + [_zero_page()] * 5
             + [_encrypted_page(i) for i in range(45, 55)]
             + [_valid_page(i) for i in range(55, 120)])
    path = _write(tmp_path, pages)
    vec = sqlpages.validate(path)
    monkeypatch.setattr(sqlpages, "_np", None)   # force the scalar path
    scal = sqlpages.validate(path)
    assert (vec.valid_pages, vec.free_space_pages, vec.anomalous_pages) == \
           (scal.valid_pages, scal.free_space_pages, scal.anomalous_pages)
    assert vec.verdict == scal.verdict
