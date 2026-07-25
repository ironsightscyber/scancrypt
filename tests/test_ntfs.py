"""NTFS extraction helpers.

The source-backed offset view and boot-sector finder are exercised directly. The
dissect.ntfs parse/list/extract path needs a real NTFS image; that is covered by an
integration test that runs only when RPRT_TEST_NTFS_IMAGE (and optionally
RPRT_TEST_NTFS_OFFSET) point at one -- otherwise it is skipped, so this suite doesn't
silently claim to test something it can't build on this host.
"""
import os
import random

import pytest

from rprt import ntfs
from rprt.source import FileSource


def _rand(n, seed):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


def test_offset_view_reads_region_as_offset_zero(tmp_path):
    base = 4096
    tail = _rand(10000, seed=1)
    p = tmp_path / "img.bin"
    p.write_bytes(_rand(base, seed=2) + tail)
    with FileSource(str(p)) as src:
        view = ntfs._SourceOffsetView(src, base)
        assert view.size == 10000
        assert view.read(100) == tail[:100]
        view.seek(500)
        assert view.read(50) == tail[500:550]
        view.seek(-20, os.SEEK_END)
        assert view.read() == tail[-20:]


def test_offset_view_readinto(tmp_path):
    p = tmp_path / "img.bin"
    data = _rand(2000, seed=3)
    p.write_bytes(data)
    with FileSource(str(p)) as src:
        view = ntfs._SourceOffsetView(src, 0)
        buf = bytearray(64)
        n = view.readinto(buf)
        assert n == 64
        assert bytes(buf) == data[:64]


def _write_bpb(buf, off):
    """Stamp a minimal but valid NTFS boot sector (BPB) at off, so _valid_bpb accepts it."""
    buf[off + 3: off + 11] = b"NTFS    "
    buf[off + 11: off + 13] = (512).to_bytes(2, "little")   # bytes per sector
    buf[off + 13] = 8                                        # sectors per cluster
    buf[off + 510: off + 512] = b"\x55\xaa"                  # boot signature


def test_find_ntfs_boot_sector_at_sector_boundary(tmp_path):
    off = 512 * 50
    buf = bytearray(_rand(512 * 128, seed=4))
    _write_bpb(buf, off)
    p = tmp_path / "d.img"
    p.write_bytes(bytes(buf))
    assert ntfs.find_ntfs_boot_sector(str(p)) == off


def test_find_ntfs_boot_sector_skips_chance_magic(tmp_path):
    # a bare 'NTFS    ' string in data (no valid BPB) must not be mistaken for a boot sector
    buf = bytearray(_rand(512 * 64, seed=8))
    buf[512 * 10 + 3: 512 * 10 + 11] = b"NTFS    "   # magic only, no 0x55AA / geometry
    p = tmp_path / "chance.img"
    p.write_bytes(bytes(buf))
    assert ntfs.find_ntfs_boot_sector(str(p)) is None


def test_find_ntfs_boot_sector_across_window_boundary(tmp_path):
    # place the magic straddling a scan-window edge to exercise the carry logic
    window = 4 * 1024 * 1024
    off = window - 4  # "NTFS    " will span the window boundary; boot sector at off-3
    buf = bytearray(_rand(window + 4096, seed=5))
    # ensure the boot sector start (off-3) lands on a 512 boundary
    boot = ((off - 3) // 512) * 512
    _write_bpb(buf, boot)
    p = tmp_path / "d2.img"
    p.write_bytes(bytes(buf))
    assert ntfs.find_ntfs_boot_sector(str(p), window=window) == boot


def test_find_ntfs_boot_sector_none_on_random(tmp_path):
    p = tmp_path / "r.img"
    p.write_bytes(_rand(2 * 1024 * 1024, seed=6))
    assert ntfs.find_ntfs_boot_sector(str(p)) is None


def test_safe_join_keeps_normal_paths(tmp_path):
    d = str(tmp_path)
    got = ntfs.safe_join(d, "/Program Files/db/data.mdf")
    assert got == os.path.join(d, "Program Files", "db", "data.mdf")
    assert os.path.realpath(got).startswith(os.path.realpath(d))


def test_safe_join_refuses_traversal(tmp_path):
    # a hostile image cannot escape the output directory
    for evil in ["../../etc/passwd", "/../../etc/passwd", "a/../../../../etc/passwd",
                 "..\\..\\Windows\\System32\\evil.dll", "../"]:
        assert ntfs.safe_join(str(tmp_path), evil) is None, evil


def test_safe_join_strips_dot_segments(tmp_path):
    got = ntfs.safe_join(str(tmp_path), "/./a/./b.txt")
    assert got == os.path.join(str(tmp_path), "a", "b.txt")


def test_mount_raises_without_dissect(monkeypatch, tmp_path):
    monkeypatch.setattr(ntfs, "_HAVE_DISSECT", False)
    p = tmp_path / "x.img"
    p.write_bytes(b"\x00" * 4096)
    assert ntfs.available() is False
    with pytest.raises(ntfs.NtfsUnavailable):
        ntfs.MountedNTFS(str(p), 0)


@pytest.mark.skipif(not os.environ.get("RPRT_TEST_NTFS_IMAGE"),
                    reason="set RPRT_TEST_NTFS_IMAGE (and optionally RPRT_TEST_NTFS_OFFSET) "
                           "to a real NTFS image to run the parse/extract integration test")
def test_real_ntfs_list_and_extract(tmp_path):
    if not ntfs.available():
        pytest.skip("dissect.ntfs not installed")
    image = os.environ["RPRT_TEST_NTFS_IMAGE"]
    base = int(os.environ.get("RPRT_TEST_NTFS_OFFSET", "0"), 0)
    with ntfs.MountedNTFS(image, base) as m:
        files = ntfs.list_files(m.fs, min_size=0)
    assert files, "expected at least one file on the volume"

    results = ntfs.extract_all(image, base, str(tmp_path), min_size=0)
    ok = [r for r in results if "error" not in r]
    assert ok, "expected at least one successful extraction"
    first = ok[0]
    assert os.path.getsize(os.path.join(tmp_path, first["path"].lstrip("/"))) == first["written"]


# ---------------------------------------------------------------- lazy directory listing

class _FakeFileName:
    """Stand-in for the $FILE_NAME dissect exposes on an index entry."""
    def __init__(self, file_attributes=0x20, file_size=0, flags=1):
        self.file_attributes = file_attributes   # 0x10 = directory, 0x400 = reparse
        self.file_size = file_size
        self.flags = flags                        # 0 POSIX, 1 Win32, 2 DOS(8.3), 3 both


class _FakeIndexEntry:
    def __init__(self, fn, seg):
        self.attribute = fn

        class _Ref:
            SegmentNumberLowPart = seg

        class _Hdr:
            FileReference = _Ref()

        self.header = _Hdr()


class _FakeDirRecord:
    def __init__(self, children):           # children: dict name -> _FakeIndexEntry
        self._children = children

    def listdir(self):
        return self._children


class _FakeFS:
    def __init__(self, by_path):            # by_path: normalized vpath -> _FakeDirRecord
        self._by_path = by_path

        class _MFT:
            def get(_self, path):
                return by_path["/" + path.replace("\\", "/").strip("/")]

        self.mft = _MFT()


def _dir(seg, flags=1):
    return _FakeIndexEntry(_FakeFileName(file_attributes=0x10, file_size=0, flags=flags), seg)


def _file(seg, size, flags=1):
    return _FakeIndexEntry(_FakeFileName(file_attributes=0x20, file_size=size, flags=flags), seg)


def _reparse_dir(seg):
    return _FakeIndexEntry(_FakeFileName(file_attributes=0x410, flags=1), seg)


def test_list_dir_filters_dos_aliases_metafiles_and_sorts():
    root = _FakeDirRecord({
        "Administrator": _dir(194, flags=1),
        "ADMINI~1": _dir(194, flags=2),        # DOS 8.3 alias of Administrator -> dropped
        "All Users": _reparse_dir(300),        # junction: listed, flagged reparse
        "desktop.ini": _file(400, 174, flags=0),
        "$MFT": _dir(0),                        # NTFS metafile -> dropped
        "notes.txt": _file(401, 12, flags=3),  # Win32&DOS single entry -> kept
    })
    fs = _FakeFS({"/": root})
    ents = ntfs.list_dir(fs, "/")
    names = [e["name"] for e in ents]
    assert names == ["Administrator", "All Users", "desktop.ini", "notes.txt"]  # dirs first
    assert "ADMINI~1" not in names and "$MFT" not in names
    by = {e["name"]: e for e in ents}
    assert by["Administrator"]["is_dir"] and by["Administrator"]["path"] == "/Administrator"
    assert by["All Users"]["reparse"] is True
    assert by["desktop.ini"]["is_dir"] is False
    assert by["desktop.ini"]["size"] == 174
    assert by["desktop.ini"]["path"] == "/desktop.ini"


def test_list_dir_nested_path_prefix():
    users = _FakeDirRecord({"austec": _dir(44191)})
    fs = _FakeFS({"/Users": users})
    ents = ntfs.list_dir(fs, "/Users")
    assert ents[0]["path"] == "/Users/austec"


def test_list_tree_recurses_skips_reparse_and_cycles():
    # /a is a dir with a file and a subdir /a/b; /a/b has a file and a reparse junction and a
    # back-reference to /a (same seg) that must not loop.
    tree = {
        "/a": _FakeDirRecord({"f1.txt": _file(10, 5), "b": _dir(20)}),
        "/a/b": _FakeDirRecord({
            "f2.txt": _file(11, 7),
            "junction": _reparse_dir(99),      # not followed
            "loop": _dir(20),                  # seg 20 already visited -> skipped
        }),
    }
    fs = _FakeFS(tree)
    got = sorted(ntfs.list_tree(fs, "/a"))
    assert got == [("/a/b/f2.txt", 7), ("/a/f1.txt", 5)]


# ---------------------------------------------------------------- virtual-disk containers

def _fixed_vhd(data: bytes) -> bytes:
    """A minimal fixed VHD: the raw disk bytes followed by a 512-byte footer."""
    import struct
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">I", f, 8, 0x00000002)            # features
    struct.pack_into(">I", f, 12, 0x00010000)           # format version
    struct.pack_into(">Q", f, 16, 0xFFFFFFFFFFFFFFFF)   # data_offset = fixed
    struct.pack_into(">Q", f, 40, len(data))            # original size
    struct.pack_into(">Q", f, 48, len(data))            # current size
    struct.pack_into(">I", f, 60, 2)                    # disk type = fixed
    struct.pack_into(">I", f, 64, (~sum(f)) & 0xFFFFFFFF)
    return data + bytes(f)


def test_container_ext_sees_through_ransomware_suffix():
    assert ntfs.container_ext("D:/vm/Disk.vhdx") == ".vhdx"
    assert ntfs.container_ext("Disk.vhdx.[AB12CD34].[a@example.org].ndm448") == ".vhdx"
    assert ntfs.container_ext("data.vmdk") == ".vmdk"
    assert ntfs.container_ext("invoices.xlsx.ndm448") is None
    assert ntfs.container_ext("disk.img") is None


@pytest.mark.skipif(not ntfs.container_available(), reason="dissect.hypervisor not installed")
def test_container_source_reads_guest_disk_linearly(tmp_path):
    data = _rand(64 * 1024, seed=11)
    p = tmp_path / "test.vhd"
    p.write_bytes(_fixed_vhd(data))
    src = ntfs.open_disk_source(str(p))
    try:
        assert src.size == len(data)
        assert src.read_at(0, 16) == data[:16]
        assert src.read_at(1000, 500) == data[1000:1500]
        assert src.read_at(len(data) + 10, 8) == b""
    finally:
        src.close()


@pytest.mark.skipif(not ntfs.container_available(), reason="dissect.hypervisor not installed")
def test_container_source_opens_ransomware_renamed_vhd(tmp_path):
    data = _rand(32 * 1024, seed=12)
    p = tmp_path / "Disk.vhd.[ID].[a@example.org].ndm448"
    p.write_bytes(_fixed_vhd(data))
    src = ntfs.open_disk_source(str(p))
    try:
        assert src.read_at(500, 200) == data[500:700]
    finally:
        src.close()


@pytest.mark.skipif(not ntfs.container_available(), reason="dissect.hypervisor not installed")
def test_damaged_container_falls_back_to_raw(tmp_path):
    # A virtual disk whose header/footer is encrypted must not raise: open_disk_source
    # degrades to a raw linear view, and container_parses reports the damage.
    data = _rand(32 * 1024, seed=21)
    good = bytearray(_fixed_vhd(data))
    good[-512:-504] = b"\x1f\x80\xf8\xd0\xf4\xe5\xdd\xd3"   # clobber the footer signature
    p = tmp_path / "disk.vhdx"
    p.write_bytes(bytes(good))
    assert ntfs.container_parses(str(p)) is False
    src = ntfs.open_disk_source(str(p))   # must not raise
    try:
        from rprt.source import FileSource
        assert isinstance(src, FileSource)
        assert src.read_at(0, 8) == data[:8]
    finally:
        src.close()


def _minimal_recoverable_vhdx(payload: bytes) -> bytes:
    """A tiny dynamic VHDX with an ENCRYPTED-looking header but intact Region Table 2,
    metadata, and BAT -- the shape the recovery reader must handle. One 1 MiB block
    (guest offset 0) points at a data region holding `payload`."""
    import struct, uuid
    BLOCK = 1 << 20
    SECTOR = 512
    META_OFF, BAT_OFF, DATA_OFF = 0x200000, 0x300000, 0x400000
    size = DATA_OFF + BLOCK
    buf = bytearray(b"\xE7" * size)          # non-zero "encrypted" filler everywhere

    def put(off, b): buf[off:off + len(b)] = b

    BAT_G = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08").bytes_le
    META_G = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
    FP_G = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B").bytes_le
    VS_G = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8").bytes_le
    LS_G = uuid.UUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F").bytes_le

    # Region Table 2 at 0x40000: header + BAT entry + METADATA entry
    put(0x40000, struct.pack("<4sIII", b"regi", 0, 2, 0))
    put(0x40010, META_G + struct.pack("<QII", META_OFF, BLOCK, 1))
    put(0x40010 + 32, BAT_G + struct.pack("<QII", BAT_OFF, BLOCK, 1))

    # Metadata region: header (count=3) + 3 entries, item data at region+0x10000
    put(META_OFF, struct.pack("<8sHH", b"metadata", 0, 3) + b"\x00" * 20)
    put(META_OFF + 32, FP_G + struct.pack("<IIII", 0x10000, 8, 0, 0))
    put(META_OFF + 64, VS_G + struct.pack("<IIII", 0x10008, 8, 0, 0))
    put(META_OFF + 96, LS_G + struct.pack("<IIII", 0x10010, 4, 0, 0))
    put(META_OFF + 0x10000, struct.pack("<II", BLOCK, 0))     # FILE_PARAMS: block_size, flags(dynamic)
    put(META_OFF + 0x10008, struct.pack("<Q", BLOCK))         # VIRTUAL_DISK_SIZE = one block
    put(META_OFF + 0x10010, struct.pack("<I", SECTOR))        # LOGICAL_SECTOR_SIZE

    # BAT: block 0 present (state 6) at DATA_OFF
    put(BAT_OFF, struct.pack("<Q", DATA_OFF | 6))
    put(DATA_OFF, payload)
    return bytes(buf)


@pytest.mark.skipif(not ntfs.container_available(), reason="dissect.hypervisor not installed")
def test_recovered_vhdx_reads_guest_via_bat(tmp_path):
    payload = b"GUEST-BLOCK-ZERO" + _rand(4096, seed=31)
    p = tmp_path / "enc.vhdx"
    p.write_bytes(_minimal_recoverable_vhdx(payload))
    # dissect can't open it (header is junk), but the recovery reader can
    assert ntfs.container_parses(str(p)) is False
    assert ntfs.disk_read_method(str(p)) == "vhdx-recovered"
    src = ntfs.open_disk_source(str(p))
    try:
        assert type(src).__name__ == "_RecoveredVhdxSource"
        assert src.read_at(0, len(payload)) == payload
        assert src.size == (1 << 20)
    finally:
        src.close()


def test_iter_partition_offsets_gpt():
    import struct

    class FakeSrc:
        def __init__(self):
            self.buf = bytearray(4096 * 512)
            h = bytearray(92); h[:8] = b"EFI PART"
            struct.pack_into("<Q", h, 72, 2)     # partition entry LBA
            struct.pack_into("<I", h, 80, 4)     # entry count
            struct.pack_into("<I", h, 84, 128)   # entry size
            self.buf[512:512 + 92] = h
            e = bytearray(128); e[:16] = b"\x11" * 16
            struct.pack_into("<Q", e, 32, 2048)  # first LBA
            self.buf[1024:1024 + 128] = e
            self.size = len(self.buf)

        def read_at(self, off, n):
            return bytes(self.buf[off:off + n])

    assert list(ntfs._iter_partition_offsets(FakeSrc())) == [2048 * 512]


def test_iter_partition_offsets_mbr():
    import struct

    class FakeSrc:
        def __init__(self):
            self.buf = bytearray(512)
            self.buf[510:512] = b"\x55\xaa"
            e = bytearray(16)
            e[4] = 0x07                            # NTFS partition type
            struct.pack_into("<I", e, 8, 128)      # first LBA
            self.buf[446:462] = e
            self.size = 512

        def read_at(self, off, n):
            return bytes(self.buf[off:off + n])

    assert list(ntfs._iter_partition_offsets(FakeSrc())) == [128 * 512]


# ---------------------------------------------------------------- Phase 1: reader contract

def _fake_recovered_reader(size, page=1 << 16):
    """A _RecoveredVhdxSource with just enough state to exercise read_at, backed by a
    deterministic synthetic disk (byte value = offset & 0xff)."""
    import collections
    r = object.__new__(ntfs._RecoveredVhdxSource)
    r.size = size
    r._cache = collections.OrderedDict()
    r._stats = None
    r._read_raw = lambda off, n: bytes((off + i) & 0xFF for i in range(n))
    return r


def test_read_at_rejects_oversized_request():
    r = _fake_recovered_reader(10 * 1024 * 1024 * 1024)
    with pytest.raises(ntfs.UnsafeReadRequest):
        r.read_at(0, ntfs.MAX_SINGLE_READ + 1)


def test_read_at_rejects_negative_offset():
    r = _fake_recovered_reader(1 << 20)
    with pytest.raises(ntfs.UnsafeReadRequest):
        r.read_at(-1, 16)


def test_read_at_bounds_and_correctness():
    size = 4 * (1 << 16)
    r = _fake_recovered_reader(size)
    assert r.read_at(size, 8) == b""            # at/after EOF
    assert r.read_at(0, 0) == b""               # zero length
    # a read spanning a page boundary returns the exact deterministic bytes
    off, n = (1 << 16) - 5, 12
    assert r.read_at(off, n) == bytes((off + i) & 0xFF for i in range(n))
    # clamped to disk end
    assert len(r.read_at(size - 4, 100)) == 4


def test_read_at_peak_memory_is_bounded():
    import tracemalloc
    r = _fake_recovered_reader(8 * 1024 * 1024 * 1024)   # 8 GiB virtual disk
    tracemalloc.start()
    r.read_at(0, ntfs.MAX_SINGLE_READ)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    # bounded by a small multiple of the cap, NOT by the 8 GiB disk size
    assert peak < 4 * ntfs.MAX_SINGLE_READ


class _FakeSeg:
    def __init__(self, segment, flags, filename, size, fp=None, fp_raises=False):
        self.segment = segment
        self.header = type("H", (), {"Flags": flags})()
        self.filename = filename
        self._size = size
        self._fp = fp
        self._fp_raises = fp_raises

    def size(self):
        return self._size

    def full_path(self):
        if self._fp_raises:
            raise ValueError("corrupt parent chain")
        return self._fp


def test_file_from_segment_normal():
    seg = _FakeSeg(100, 0x01, "data.mdf", 5000, fp="/db/data.mdf")
    assert ntfs._file_from_segment(seg, 0) == ("/db/data.mdf", 5000)


def test_file_from_segment_skips_dir_metafile_and_small():
    assert ntfs._file_from_segment(_FakeSeg(100, 0x03, "dir", 0), 0) is None       # directory
    assert ntfs._file_from_segment(_FakeSeg(5, 0x01, "$MFT", 0), 0) is None         # metafile #
    assert ntfs._file_from_segment(_FakeSeg(100, 0x01, "$x", 0), 0) is None         # $-name
    assert ntfs._file_from_segment(_FakeSeg(100, 0x01, "a", 10), 1000) is None      # < min_size
    assert ntfs._file_from_segment(_FakeSeg(100, 0x00, "a", 10), 0) is None         # not in use


def test_file_from_segment_path_fallback_on_failure():
    # a path-resolution failure must not drop the file; content recovered under synthetic path
    seg = _FakeSeg(1234, 0x01, "important.db", 900, fp_raises=True)
    got = ntfs._file_from_segment(seg, 0)
    assert got == ("/__unresolved__/mft_1234_important.db", 900)


def test_file_from_segment_path_fallback_on_sentinel():
    seg = _FakeSeg(1234, 0x01, "important.db", 900, fp="/a/<unknown_segment_0x5>/x")
    assert ntfs._file_from_segment(seg, 0)[0].startswith("/__unresolved__/mft_1234_")


class _FakeRec:
    def __init__(self, size, data):
        self._size = size
        self._data = data

    def size(self):
        return self._size

    def open(self):
        import io
        return io.BytesIO(self._data)


def test_extract_record_caps_at_declared_size(tmp_path):
    # declared size 5 but 100 bytes available -> only 5 written (no runaway)
    rec = _FakeRec(5, b"x" * 100)
    dest = str(tmp_path / "out.bin")
    written, _ = ntfs._extract_record(rec, dest)
    assert written == 5 and os.path.getsize(dest) == 5


def test_extract_record_rejects_implausible_size(tmp_path):
    rec = _FakeRec(ntfs.MAX_FILE_BYTES + 1, b"")
    with pytest.raises(ntfs.UnsafeReadRequest):
        ntfs._extract_record(rec, str(tmp_path / "out.bin"))


# --- mft_coverage: honest partial-listing detection (F3) --------------------------------
class _CovRec:
    def __init__(self, data):
        self._data = data

    def open(self):
        import io
        return io.BytesIO(self._data)


class _CovMft:
    def __init__(self, data):
        self._rec = _CovRec(data)

    def get(self, i):
        assert i == 0
        return self._rec


class _CovFs:
    def __init__(self, data):
        self.mft = _CovMft(data)
        self._record_size = 1024


def _mft_bytes(specs, rsize=1024):
    out = bytearray()
    for s in specs:
        if s == "file":
            out += b"FILE" + b"\x00" * (rsize - 4)
        elif s == "zero":
            out += b"\x00" * rsize
        else:  # garbage: non-zero, non-FILE
            out += b"\xde\xad" + b"\x11" * (rsize - 2)
    return bytes(out)


def test_mft_coverage_ignores_reserved_zero_records():
    # records 12-23 are reserved and legitimately zero on a healthy volume -> NOT damage
    specs = ["file"] * 12 + ["zero"] * 12 + ["file"] * 76
    cov = ntfs.mft_coverage(_CovFs(_mft_bytes(specs)))
    assert cov["missing_in_range"] == 0


def test_mft_coverage_flags_hole_in_user_range():
    # a zero record at index 30 (>= 27), below the highest used record -> a real hole
    specs = ["file"] * 30 + ["zero"] + ["file"] * 20
    cov = ntfs.mft_coverage(_CovFs(_mft_bytes(specs)))
    assert cov["missing_in_range"] == 1


def test_mft_coverage_flags_garbage_in_user_range():
    specs = ["file"] * 40 + ["garbage"] * 2 + ["file"] * 10
    cov = ntfs.mft_coverage(_CovFs(_mft_bytes(specs)))
    assert cov["missing_in_range"] == 2


def test_mft_coverage_ignores_never_used_zero_tail():
    # zero records ABOVE the highest used record are the normal unallocated tail, not damage
    specs = ["file"] * 30 + ["zero"] * 20
    cov = ntfs.mft_coverage(_CovFs(_mft_bytes(specs)))
    assert cov["missing_in_range"] == 0
