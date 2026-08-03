"""rprt.ntfs — read files out of an intact NTFS volume inside a partially-encrypted image.

When the front of a disk image (a fixed VHDX's header, say) is encrypted but the NTFS
volume inside it is untouched, the files are fully recoverable by parsing the filesystem
directly at the volume's byte offset -- no need to repair the container. This is how the
SQL data/log files were pulled off the encrypted disks in the validated incident.

Backed by rprt.source, so it reads from a regular file, a disk image, OR (on Windows, as
Administrator) a raw device -- the same read-only input abstraction the scanner uses.

Requires `dissect.ntfs` (an optional dependency): `pip install "rprt[ntfs]"`. Everything
else in rprt works without it; only this module needs it.

Gotcha already solved (from the prototype): dissect.ntfs's iterdir() yields IndexEntry
objects, not file records -- call .dereference() before reading name/size/opening.
"""
from __future__ import annotations

import hashlib
import io
import os
from typing import Callable, List, Optional, Tuple

from .source import open_source

try:
    from dissect.ntfs import NTFS
    _HAVE_DISSECT = True
except ImportError:
    NTFS = None
    _HAVE_DISSECT = False

try:
    from dissect.hypervisor.disk import vhdx as _vhdx, vhd as _vhd, vmdk as _vmdk
    _HAVE_HYPERVISOR = True
except ImportError:
    _HAVE_HYPERVISOR = False

ProgressFn = Optional[Callable[[float, str], None]]

# Virtual-disk containers we can read through. A dynamic VHDX scatters the guest disk's
# blocks across the file, so there is no linear NTFS offset in the raw bytes; the container
# parser reassembles the guest disk in order.
CONTAINER_EXTS = {".vhdx", ".vhd", ".vmdk"}

# --- Reader safety limits ---------------------------------------------------------------
# The low-level virtual-disk reader treats every (offset, length) as UNTRUSTED, even when it
# comes from a trusted library: on a partially-encrypted disk the "library" is parsing
# garbage, and a corrupted NTFS length can otherwise be amplified into a huge allocation.
#
# MAX_SINGLE_READ: hard ceiling on one read_at call. The largest request seen during normal
# extraction is ~1 MiB (measured); file copies stream in <=8 MiB chunks. 64 MiB is far above
# anything legitimate, so only a value derived from corrupt metadata trips it.
MAX_SINGLE_READ = 64 * 1024 * 1024
# Largest plausible single file. A real file cannot exceed the disk; 16 TiB is a generous
# sanity bound. A record claiming more is corrupt, not a giant file, and is refused rather
# than copied (which would otherwise write until the output disk fills).
MAX_FILE_BYTES = 16 * 1024 ** 4
# Env-gated read statistics for the investigation harness (off in production).
_READER_STATS = (os.environ.get("SCANCRYPT_READER_STATS")
                 or os.environ.get("RPRT_READER_STATS")) == "1"
_READER_STATS_TOTAL = ({"readers": 0, "reads": 0, "max_len": 0, "max_off": 0,
                        "rejected": 0, "hist": {}} if _READER_STATS else None)


def reader_stats():
    """Aggregate recovered-VHDX read statistics for this process, or None unless
    SCANCRYPT_READER_STATS=1. For the investigation harness: largest request, offset reach,
    log2 length histogram, and count of requests refused for exceeding MAX_SINGLE_READ."""
    return dict(_READER_STATS_TOTAL) if _READER_STATS_TOTAL is not None else None


class UnsafeReadRequest(ValueError):
    """A read whose length exceeds MAX_SINGLE_READ (or a negative/invalid offset): a request
    driven by corrupted on-disk metadata, not a real access. Callers catch this, record it,
    and skip the offending record rather than crash."""

    def __init__(self, offset, length):
        super().__init__(f"unsafe read: length {length} at offset {offset} "
                         f"(cap {MAX_SINGLE_READ})")
        self.offset = offset
        self.length = length


def container_available() -> bool:
    return _HAVE_HYPERVISOR


def _is_pow2(x: int) -> bool:
    return isinstance(x, int) and x > 0 and (x & (x - 1)) == 0


def _uuid_le(guid: str) -> bytes:
    """VHDX stores GUIDs in mixed-endian (little-endian first three fields), the same layout
    Python's uuid.UUID.bytes_le produces. Turn a canonical GUID string into those raw bytes
    so we can match region/metadata identifiers read straight from the file."""
    import uuid
    return uuid.UUID(guid).bytes_le


def container_ext(path: str) -> Optional[str]:
    """The virtual-disk container extension in `path`, looking past any extension the
    ransomware appended (disk.vhdx.[id].ndm448 -> .vhdx). None if not a container."""
    name = os.path.basename(path).lower()
    for part in reversed(name.split(".")):
        ext = "." + part
        if ext in CONTAINER_EXTS:
            return ext
    return None


class _ContainerSource:
    """Adapts a dissect.hypervisor virtual-disk (VHDX/VHD/VMDK) to the rprt source
    interface (read_at, size, close), so the NTFS walker sees the guest disk in linear
    order regardless of how the container stores its blocks."""

    def __init__(self, path: str):
        if not _HAVE_HYPERVISOR:
            raise NtfsUnavailable(
                "Reading virtual disks needs dissect.hypervisor. Install it with: "
                "pip install \"rprt[ntfs]\"")
        import pathlib
        ext = container_ext(path) or os.path.splitext(path)[1].lower()
        self._fh = None
        if ext == ".vmdk":
            self._fh = open(path, "rb")
            self._disk = _vmdk.VMDK(self._fh)
        elif ext == ".vhd":
            self._fh = open(path, "rb")
            self._disk = _vhd.VHD(self._fh)
        else:
            # Pass a Path (not a handle) so a differencing VHDX resolves its parent chain
            # from the same directory. Falls back to a handle if the parent is unavailable.
            try:
                self._disk = _vhdx.VHDX(pathlib.Path(path))
            except Exception:
                self._fh = open(path, "rb")
                self._disk = _vhdx.VHDX(self._fh)
        self.size = int(self._disk.size)

    def read_at(self, offset: int, n: int) -> bytes:
        if offset >= self.size:
            return b""
        return self._disk.readoffset(offset, min(n, self.size - offset))

    def close(self):
        for obj in (getattr(self, "_disk", None), self._fh):
            try:
                if obj is not None:
                    obj.close()
            except Exception:  # noqa: BLE001
                pass


# VHDX on-disk GUIDs (little-endian in file); used to recover a disk whose header the
# ransomware encrypted, by reading the redundant structures that survived further in.
_VHDX_BAT_GUID = _uuid_le("2DC27766-F623-4200-9D64-115E9BFD4A08")
_VHDX_META_GUID = _uuid_le("8B7CA206-4790-4B9A-B8FE-575F050F886E")
_VHDX_FILE_PARAMS = _uuid_le("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
_VHDX_VIRTUAL_SIZE = _uuid_le("2FA54224-CD1B-4876-B211-5DBED83BF4B8")
_VHDX_LOGICAL_SECTOR = _uuid_le("8141BF1D-A96F-4709-BA47-F233A8FAAB5F")
# The two region-table copies sit at fixed offsets, independent of the (possibly encrypted)
# headers. Reading either one gets us the BAT and metadata locations.
_VHDX_REGION_TABLE_OFFSETS = (0x40000, 0x30000)


class _RecoveredVhdxSource:
    """Reads a VHDX whose header the ransomware encrypted, by reconstructing the guest disk
    from the structures that survived past the encrypted front: a region-table copy (fixed
    offset), the metadata region (geometry), and the block-allocation table (guest->file
    block map). This is what makes a dynamic VHDX recoverable when its 'vhdxfile' signature
    is gone, so dissect.hypervisor can't open it. Raises if the surviving structures aren't
    there (encryption reached them) or the disk is differencing (needs a parent chain)."""

    def __init__(self, path: str):
        import struct
        from collections import OrderedDict
        self._fh = open(path, "rb")
        self._cache = OrderedDict()
        self._stats = {"reads": 0, "max_len": 0, "max_off": 0, "rejected": 0,
                       "hist": {}} if _READER_STATS else None
        try:
            regions = self._read_region_table(struct)
            if _VHDX_BAT_GUID not in regions or _VHDX_META_GUID not in regions:
                raise ValueError("VHDX region table lacks BAT/metadata (encrypted?)")
            self._parse_metadata(struct, *regions[_VHDX_META_GUID])
            bat_off, _ = regions[_VHDX_BAT_GUID]
            self._fh.seek(bat_off)
            self._bat = self._fh.read(1 << 20)   # BAT region is 1 MiB
            self._chunk_ratio = ((2 ** 23) * self._sector) // self._block
        except Exception:
            self._fh.close()
            raise

    def _read_region_table(self, struct):
        for base in _VHDX_REGION_TABLE_OFFSETS:
            self._fh.seek(base)
            hdr = self._fh.read(16)
            if len(hdr) < 16 or hdr[:4] != b"regi":
                continue
            _, _, count, _ = struct.unpack("<4sIII", hdr)
            regions = {}
            for _ in range(min(count, 2047)):
                e = self._fh.read(32)
                if len(e) < 32:
                    break
                guid = e[:16]
                foff, length, _req = struct.unpack("<QII", e[16:32])
                regions[guid] = (foff, length)
            if regions:
                return regions
        raise ValueError("no intact VHDX region table (both copies encrypted?)")

    def _parse_metadata(self, struct, meta_off, meta_len):
        self._fh.seek(meta_off)
        md = self._fh.read(min(meta_len, 1 << 20))
        if md[:8] != b"metadata":
            raise ValueError("VHDX metadata region encrypted or missing")
        _, _, count = struct.unpack("<8sHH", md[:12])
        self._block = self._sector = self._size = None
        has_parent = False
        # The metadata table has a handful of entries; a corrupt count must not drive the loop.
        for i in range(min(count, 64)):
            e = md[32 + i * 32: 64 + i * 32]
            if len(e) < 32:
                break
            guid = e[:16]
            ioff, ilen = struct.unpack("<II", e[16:24])
            if ioff + ilen > len(md) or ilen > 4096:      # item must lie within the region
                continue
            val = md[ioff:ioff + ilen]
            if guid == _VHDX_FILE_PARAMS and len(val) >= 8:
                self._block, flags = struct.unpack("<II", val[:8])
                has_parent = bool((flags >> 1) & 1)
            elif guid == _VHDX_VIRTUAL_SIZE and len(val) >= 8:
                self._size = struct.unpack("<Q", val[:8])[0]
            elif guid == _VHDX_LOGICAL_SECTOR and len(val) >= 4:
                self._sector = struct.unpack("<I", val[:4])[0]
        if has_parent:
            raise ValueError("differencing VHDX needs its parent chain")
        if not (self._block and self._sector and self._size):
            raise ValueError("VHDX metadata incomplete")
        # Reject impossible geometry before it can poison the BAT translation: a wrong block
        # or sector size makes every guest offset map to the wrong physical byte, turning the
        # whole reconstructed disk into noise the filesystem parser then chokes on.
        if self._sector not in (512, 4096):
            raise ValueError(f"implausible VHDX logical sector size {self._sector}")
        if not _is_pow2(self._block) or not (1 << 20) <= self._block <= (256 << 20):
            raise ValueError(f"implausible VHDX block size {self._block}")
        if self._size <= 0 or self._size % self._sector != 0:
            raise ValueError(f"implausible VHDX virtual size {self._size}")
        # A 1 MiB BAT holds 131072 8-byte entries; the disk cannot need more payload blocks.
        if self._size // self._block > (1 << 20) // 8:
            raise ValueError("VHDX virtual size exceeds BAT capacity (metadata corrupt?)")
        self.size = int(self._size)

    # Filesystem parsing does hundreds of thousands of small, repeated reads (the MFT, index
    # blocks). Each one otherwise seeks through the BAT-mapped file, which crawls on a big
    # volume. An LRU page cache turns the repeated/nearby reads into memory hits.
    _PAGE = 1 << 16          # 64 KiB
    _MAX_PAGES = 4096        # cap ~256 MiB

    def _read_raw(self, offset: int, n: int) -> bytes:
        import struct
        out = bytearray()
        while n > 0:
            blk = offset // self._block
            within = offset % self._block
            take = min(n, self._block - within)
            idx = blk + blk // self._chunk_ratio        # skip interleaved sector-bitmap entries
            ent = struct.unpack_from("<Q", self._bat, idx * 8)[0] if idx * 8 + 8 <= len(self._bat) else 0
            if ent & 7 in (6, 7):                        # (partially) present -> read from file
                self._fh.seek(((ent >> 20) << 20) + within)
                out += self._fh.read(take)
            else:                                        # unallocated/zero block
                out += b"\x00" * take
            offset += take
            n -= take
        return bytes(out)

    def read_at(self, offset: int, n: int) -> bytes:
        # Untrusted-input contract: offset/length may be driven by corrupted NTFS metadata.
        if not isinstance(offset, int) or not isinstance(n, int):
            raise TypeError("read offset and length must be integers")
        if offset < 0:
            raise UnsafeReadRequest(offset, n)
        if n <= 0 or offset >= self.size:
            return b""
        if n > MAX_SINGLE_READ:                       # refuse; never amplify into a huge alloc
            if self._stats is not None:
                self._stats["rejected"] += 1
            raise UnsafeReadRequest(offset, n)
        n = min(n, self.size - offset)                # clamp to disk bounds (Python: no overflow)
        if self._stats is not None:
            s = self._stats
            s["reads"] += 1
            s["max_len"] = max(s["max_len"], n)
            s["max_off"] = max(s["max_off"], offset)
            b = n.bit_length()
            s["hist"][b] = s["hist"].get(b, 0) + 1
        # Assemble into one preallocated buffer, copying only the requested slice of each
        # touched page. Peak memory is bounded by n (<= MAX_SINGLE_READ), not by a parts list
        # plus a join. A short physical read leaves that tail zero-filled (honest: unreadable).
        out = bytearray(n)
        pos = 0
        page = offset // self._PAGE
        page_off = offset - page * self._PAGE
        while pos < n:
            data = self._cache.get(page)
            if data is None:
                data = self._read_raw(page * self._PAGE, self._PAGE)
                self._cache[page] = data
                if len(self._cache) > self._MAX_PAGES:
                    self._cache.popitem(last=False)
            else:
                self._cache.move_to_end(page)
            take = min(self._PAGE - page_off, n - pos)
            avail = min(len(data) - page_off, take)
            if avail > 0:
                out[pos:pos + avail] = data[page_off:page_off + avail]
            pos += take
            page += 1
            page_off = 0
        return bytes(out)

    def stats(self):
        return dict(self._stats) if self._stats is not None else None

    def close(self):
        if self._stats is not None and _READER_STATS_TOTAL is not None:
            t, s = _READER_STATS_TOTAL, self._stats
            t["readers"] += 1
            t["reads"] += s["reads"]
            t["rejected"] += s["rejected"]
            t["max_len"] = max(t["max_len"], s["max_len"])
            t["max_off"] = max(t["max_off"], s["max_off"])
            for k, v in s["hist"].items():
                t["hist"][k] = t["hist"].get(k, 0) + v
        try:
            self._fh.close()
        except Exception:  # noqa: BLE001
            pass


def disk_type(path: str) -> Optional[str]:
    """Best-effort virtual-disk type: 'fixed', 'dynamic', 'differencing', or None when the
    container header can't be read (e.g. it was encrypted). Purely informational, to explain
    to the user what kind of disk they have and why a given recovery path applies."""
    if container_ext(path) is None or not _HAVE_HYPERVISOR:
        return None
    try:
        src = _ContainerSource(path)
    except Exception:  # noqa: BLE001
        return None
    try:
        disk = src._disk
        if getattr(disk, "has_parent", False):
            return "differencing"
        # dissect exposes block_size on dynamic/differencing VHDX; fixed disks read linearly.
        cls = type(disk).__name__
        if "Fixed" in cls:
            return "fixed"
        return "dynamic" if getattr(disk, "block_size", None) else "fixed"
    except Exception:  # noqa: BLE001
        return None
    finally:
        src.close()


def disk_read_method(path: str) -> Optional[str]:
    """Which reader open_disk_source will use for `path`:
      'container'      -- dissect.hypervisor opened the intact header (any disk type)
      'vhdx-recovered' -- header encrypted, but the disk was rebuilt from its surviving
                          region table + metadata + BAT (a complete reconstruction)
      'raw'            -- read as a flat image (fixed disk, or a non-container file)
    """
    ext = container_ext(path)
    if ext is None:
        return "raw"
    if container_parses(path):
        return "container"
    if ext == ".vhdx":
        try:
            _RecoveredVhdxSource(path).close()
            return "vhdx-recovered"
        except Exception:  # noqa: BLE001
            pass
    return "raw"


def disk_geometry(path: str):
    """Best-effort VHDX geometry for diagnostics: {block, sector, virtual_size} when the disk
    is read through the recovered-VHDX reader (encrypted header), else None. Never raises."""
    try:
        if container_ext(path) == ".vhdx" and not container_parses(path):
            src = _RecoveredVhdxSource(path)
            try:
                return {"block": src._block, "sector": src._sector, "virtual_size": src.size}
            finally:
                src.close()
    except Exception:  # noqa: BLE001
        return None
    return None


def container_parses(path: str) -> bool:
    """True if the virtual-disk container header is intact enough to open. False when the
    input is not a container, dissect.hypervisor is missing, or the header is damaged --
    e.g. the ransomware encrypted the front of the file, where the VHDX header lives."""
    if container_ext(path) is None or not _HAVE_HYPERVISOR:
        return False
    try:
        _ContainerSource(path).close()
        return True
    except Exception:  # noqa: BLE001
        return False


def open_disk_source(path: str):
    """Open `path` as a linear guest disk, trying the most capable reader first:

    1. dissect.hypervisor container parse -- works when the header is intact (any type).
    2. VHDX recovery reader -- when the header is encrypted but the region table, metadata
       and BAT survived further in (the common ransomware case), it rebuilds the guest disk
       from those, so even a dynamic disk with scattered blocks reads in guest order.
    3. raw linear view -- last resort; recovers a fixed disk whose payload is laid out
       linearly after the header region.
    """
    ext = container_ext(path)
    if ext is not None:
        try:
            return _ContainerSource(path)
        except Exception:  # noqa: BLE001 -- header unreadable; try recovering from survivors
            pass
        if ext == ".vhdx":
            try:
                return _RecoveredVhdxSource(path)
            except Exception:  # noqa: BLE001 -- survivors gone too; fall through to raw
                pass
    return open_source(path)


class NtfsUnavailable(RuntimeError):
    """Raised when NTFS support is requested but dissect.ntfs isn't installed."""


def available() -> bool:
    return _HAVE_DISSECT


class _SourceOffsetView(io.RawIOBase):
    """Presents the region of a source starting at byte `base` as an independent stream
    at offset 0, so a filesystem parser can mount a volume that lives partway into a
    larger image -- over a file or a raw device alike."""

    def __init__(self, src, base: int):
        self._src = src
        self._base = base
        self.size = max(src.size - base, 0)
        self._pos = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self.size + offset
        return self._pos

    def tell(self):
        return self._pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self._pos
        data = self._src.read_at(self._base + self._pos, n)
        self._pos += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)


class MountedNTFS:
    """An open NTFS volume plus the underlying source. Use as a context manager so the
    source is closed when done. `fs` is the dissect.ntfs NTFS object."""

    def __init__(self, path: str, base: int):
        if not _HAVE_DISSECT:
            raise NtfsUnavailable(
                "NTFS support needs dissect.ntfs. Install it with: pip install \"rprt[ntfs]\"")
        self._src = open_disk_source(path)
        self._view = _SourceOffsetView(self._src, base)
        self.base = base
        self.fs = NTFS(self._view)

    def close(self):
        try:
            self._src.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _iter_boot_sector_offsets(src, search_limit: int, window: int):
    """Yield every 512-aligned offset where the 'NTFS    ' OEM ID sits at boot-sector
    offset 3. These are candidates only; a chance occurrence in file data looks identical
    to a real boot sector here, so callers must validate (see _valid_bpb / find_ntfs_volume)."""
    limit = min(search_limit, src.size)
    off = 0
    carry = b""
    while off < limit:
        chunk = src.read_at(off, min(window, limit - off))
        if not chunk:
            break
        buf = carry + chunk
        idx = 0
        while True:
            idx = buf.find(b"NTFS    ", idx)
            if idx < 0:
                break
            candidate = (off - len(carry)) + idx - 3
            if candidate >= 0 and candidate % 512 == 0:
                yield candidate
            idx += 1
        carry = buf[-8:]  # keep enough tail to catch a magic split across chunks
        off += len(chunk)


def _valid_bpb(boot: bytes) -> bool:
    """True if a 512-byte block is a plausible NTFS boot sector, not a chance 'NTFS    '
    string in data. Checks the 0x55AA end signature and sane BPB geometry -- a strong
    filter, since random data almost never carries all three."""
    if len(boot) < 512 or boot[3:11] != b"NTFS    ":
        return False
    if boot[510:512] != b"\x55\xaa":
        return False
    if int.from_bytes(boot[11:13], "little") not in (256, 512, 1024, 2048, 4096):
        return False
    if boot[13] not in (1, 2, 4, 8, 16, 32, 64, 128):   # sectors per cluster
        return False
    return True


def find_ntfs_boot_sector(path: str, search_limit: int = 128 * 1024 * 1024,
                          window: int = 4 * 1024 * 1024) -> Optional[int]:
    """First offset whose boot sector passes a BPB sanity check. Kept for callers that only
    need a candidate offset; prefer find_ntfs_volume, which also confirms the MFT reads."""
    src = open_disk_source(path)
    try:
        for off in _iter_boot_sector_offsets(src, search_limit, window):
            if _valid_bpb(src.read_at(off, 512)):
                return off
        return None
    finally:
        src.close()


def _iter_partition_offsets(src):
    """Yield the byte offset of each partition on the guest disk, GPT first, then MBR. This
    turns a slow brute-force sweep into a few small, targeted reads: on a dynamic disk a
    linear scan seeks wildly (guest block 1 can live tens of GB into the file), but the
    partition table sits in block 0 and tells us exactly where each volume starts."""
    import struct
    sector = 512
    # GPT: header at guest LBA 1 with an 'EFI PART' signature.
    gpt = src.read_at(sector, 92)
    if gpt[:8] == b"EFI PART":
        entry_lba = struct.unpack("<Q", gpt[72:80])[0]
        count = min(struct.unpack("<I", gpt[80:84])[0], 256)
        esize = struct.unpack("<I", gpt[84:88])[0] or 128
        table = src.read_at(entry_lba * sector, count * esize)
        for i in range(count):
            e = table[i * esize: i * esize + esize]
            if len(e) < 48 or e[:16] == b"\x00" * 16:      # unused entry
                continue
            first_lba = struct.unpack("<Q", e[32:40])[0]
            if first_lba:
                yield first_lba * sector
        return
    # MBR fallback: 0x55AA signature, four 16-byte entries at offset 446.
    mbr = src.read_at(0, 512)
    if mbr[510:512] == b"\x55\xaa":
        for i in range(4):
            e = mbr[446 + i * 16: 462 + i * 16]
            ptype = e[4]
            first_lba = struct.unpack("<I", e[8:12])[0]
            if ptype in (0x07, 0x17, 0x27) and first_lba:    # NTFS / hidden-NTFS / recovery
                yield first_lba * sector


def find_ntfs_volume(path: str, search_limit: int = 512 * 1024 * 1024,
                     window: int = 4 * 1024 * 1024, max_candidates: int = 64) -> Optional[int]:
    """Locate a genuinely mountable NTFS volume and return its base offset, or None.

    First we read the guest partition table and check each partition's start -- fast and
    exact, even on a dynamic disk whose blocks are scattered across the file. Only if there
    is no usable partition table do we fall back to a bounded boot-sector sweep. Either way a
    candidate is trusted only after its MFT actually parses, which rejects a chance 'NTFS    '
    string in file data and a real boot sector whose MFT a linear read would misplace."""
    src = open_disk_source(path)
    try:
        def usable(off):
            if not _valid_bpb(src.read_at(off, 512)):
                return False
            try:
                with MountedNTFS(path, off) as m:
                    m.fs.mft.get("/")   # forces the first MFT record read; raises on garbage
                return True
            except Exception:  # noqa: BLE001
                return False

        # 1. Partition-table directed (the fast path).
        try:
            for off in _iter_partition_offsets(src):
                if usable(off):
                    return off
        except Exception:  # noqa: BLE001 -- unreadable partition table; fall back to the sweep
            pass

        # 2. Bounded boot-sector sweep (no or damaged partition table).
        checked = 0
        for off in _iter_boot_sector_offsets(src, search_limit, window):
            if not _valid_bpb(src.read_at(off, 512)):
                continue
            checked += 1
            if checked > max_candidates:
                break
            if usable(off):
                return off
        return None
    finally:
        src.close()


def _name(rec):
    n = rec.filename
    return n() if callable(n) else n


def _is_dir(rec):
    d = rec.is_dir
    return d() if callable(d) else d


def _in_use_file(seg) -> bool:
    """True for an allocated (not deleted) file record. The MFT header Flags field has
    bit 0 = in use, bit 1 = directory."""
    try:
        flags = seg.header.Flags
        return bool(flags & 0x01) and not (flags & 0x02)
    except Exception:  # noqa: BLE001
        return False


def _record_size(fs) -> int:
    """NTFS file-record size, from the boot sector (dissect derives it there); never assume
    1024, which is only the default when no boot sector is present."""
    return getattr(fs, "_record_size", None) or 1024


def _total_mft_records(fs) -> int:
    """Record count from the $MFT size and the boot-sector-derived record size, for progress
    and for bounding an index walk."""
    try:
        return max(fs.mft.get(0).size() // _record_size(fs), 1)
    except Exception:  # noqa: BLE001
        return 0


# NTFS reserves MFT records 0-26 for system metafiles ($MFT..$Extend and its children);
# user files start at record 27. Records 12-23 are reserved and legitimately zero-filled.
_MFT_FIRST_USER_RECORD = 27


def mft_coverage(fs):
    """Detect a silently-partial MFT: records that read as zero/garbage *within* the used
    range of the $MFT because their backing clusters did not survive (the encrypted front,
    or an unmapped virtual-disk block), as distinct from the normal zero tail of
    never-allocated records. Returns a dict or None if it can't be determined.

    Every live NTFS $MFT record starts with the 'FILE' magic whether it is in use or free;
    a slot that is all-zero (or lacks 'FILE') *below the highest used record* is a hole --
    its cluster was not recoverable. Reading the $MFT's own data stream once (it is tiny
    next to the disk) lets us count those holes and honestly flag the listing as partial,
    instead of silently returning a truncated file list as if it were complete.

    Records 0-26 are NTFS system metafiles; 12-23 are reserved and legitimately zero on a
    healthy volume, so holes there are NOT damage and must not be counted (they would
    otherwise false-alarm on a perfectly recovered disk). Only holes at record >= 27 -- the
    range that holds user files -- count toward a partial verdict."""
    rsize = _record_size(fs)
    if rsize <= 0:
        return None
    try:
        stream = fs.mft.get(0).open()
    except Exception:  # noqa: BLE001
        return None
    present = 0
    last_used = -1
    holes = 0
    holes_below_high_water = 0
    idx = 0
    carry = b""
    try:
        while True:
            chunk = stream.read(1 << 20)      # 1 MiB of $MFT at a time
            buf = carry + chunk
            n = len(buf) // rsize
            for k in range(n):
                rec = buf[k * rsize:(k + 1) * rsize]
                if rec[:4] == b"FILE":
                    present += 1
                    if idx > last_used:
                        holes_below_high_water += holes
                        holes = 0
                    last_used = idx
                elif idx >= _MFT_FIRST_USER_RECORD:   # zero/garbage in the user-file range
                    holes += 1
                # else: reserved system record (0-26); a zero here is normal, not damage
                idx += 1
            carry = buf[n * rsize:]
            if not chunk:
                break
    except Exception:  # noqa: BLE001 -- stream read failed partway; report what we have
        pass
    return {
        "declared_records": idx,
        "present_records": present,
        "missing_in_range": holes_below_high_water,   # holes below the highest used record
        "last_used_index": last_used,
    }


def _file_from_segment(seg, min_size: int):
    """(vpath, size) for an allocated, large-enough real file record, or None to skip it.
    Never raises. A path-resolution failure does NOT drop the file: its content is recovered
    under a synthetic path, so a corrupt directory tree can't cost us recoverable data."""
    try:
        num = seg.segment
        if num is not None and num < _MFT_FIRST_USER_RECORD:   # NTFS reserved metafiles
            return None
        if not _in_use_file(seg):
            return None
        name = _name(seg)
        if not name or str(name).startswith("$"):
            return None
        size = seg.size()
        if size < min_size:
            return None
    except Exception:  # noqa: BLE001 -- unreadable record; skip
        return None
    try:
        path = seg.full_path()
    except Exception:  # noqa: BLE001
        path = None
    # dissect encodes unresolved parents as <recursion> / <unknown_segment_..> sentinels.
    if not path or "<" in str(path):
        path = "/__unresolved__/mft_%s_%s" % (num, name)
    return "/" + str(path).replace("\\", "/").lstrip("/"), size


def _iter_records(fs, cancel_check=None):
    """Yield MFT records by index with per-record fault isolation: a single garbage record
    (which can raise deep in dissect's parser) is skipped, not fatal to the whole walk.
    Iterating by index rather than through segments() is what makes that isolation possible;
    a generator that raises mid-iteration cannot be resumed."""
    total = _total_mft_records(fs)
    if total <= 0:
        return
    for i in range(total):
        if cancel_check is not None and cancel_check():
            return
        try:
            seg = fs.mft.get(i)
        except Exception:  # noqa: BLE001 -- unreadable/garbage record; skip
            continue
        yield i, seg


def iter_volume_files(fs, min_size: int = 0, cancel_check=None):
    """Yield (record, path, size) for every allocated file on the volume, walking the MFT by
    index with per-record isolation. Much faster than a recursive directory descent, and a
    single bad record cannot abort the walk."""
    for _i, seg in _iter_records(fs, cancel_check):
        got = _file_from_segment(seg, min_size)
        if got is not None:
            yield seg, got[0], got[1]


def list_files(fs, min_size: int = 0, cancel_check=None) -> List[Tuple[str, int]]:
    """(path, size) for every allocated file >= min_size, via the fast linear MFT walk."""
    return [(p, s) for _, p, s in iter_volume_files(fs, min_size, cancel_check)]


# ---- lazy per-directory listing (the browse tree reads one folder at a time) -----------
# The flat MFT walk above is right for "extract everything" and for building a global search
# index, but wrong for interactive browsing: it reads all ~250k records before showing
# anything. These read one directory's index instead, so the tree opens instantly and a
# folder is only touched when it is expanded.

_FILE_ATTR_DIRECTORY = 0x10        # FILE_ATTRIBUTE_DIRECTORY, in the $FILE_NAME attributes
_FILE_ATTR_REPARSE = 0x400         # FILE_ATTRIBUTE_REPARSE_POINT (junction/symlink)
_FN_NAMESPACE_DOS = 2              # $FILE_NAME namespace: 0=POSIX 1=Win32 2=DOS(8.3) 3=both


def _child_entry(name, ie):
    """Describe one directory child straight from its index entry's embedded $FILE_NAME, or
    None to skip it. Reading name/size/is-dir from the index means a directory lists in
    milliseconds without opening each child's own record. Never raises."""
    try:
        a = ie.attribute                       # the $FILE_NAME carried in the index entry
        if a is None:
            return None
        # A long name and its DOS 8.3 alias are two index entries pointing at the same record;
        # dropping the DOS-namespace one removes the "ADMINI~1 beside Administrator" duplicate.
        if getattr(a, "flags", None) == _FN_NAMESPACE_DOS:
            return None
        nm = str(name)
        if nm in (".", "..") or nm.startswith("$"):   # self, parent, NTFS metafiles
            return None
        attrs = int(getattr(a, "file_attributes", 0) or 0)
        is_dir = bool(attrs & _FILE_ATTR_DIRECTORY)
        seg = ie.header.FileReference.SegmentNumberLowPart
    except Exception:  # noqa: BLE001 -- unreadable entry; skip it, don't abort the listing
        return None
    size = None if is_dir else int(getattr(a, "file_size", 0) or 0)
    return {"name": nm, "is_dir": is_dir, "size": size,
            "reparse": bool(attrs & _FILE_ATTR_REPARSE), "seg": seg}


def list_dir(fs, vpath: str = "/") -> List[dict]:
    """Immediate children of one directory, read from its index alone. Returns a list of
    {name, path, is_dir, size, reparse, seg} dicts -- directories first, then files, each
    sorted by name. `size` is None for a directory (its rolled-up total, when wanted, comes
    from the background scan). Read-only, with per-child fault isolation, so one bad index
    entry is skipped rather than fatal. This is what lets the browse tree open instantly and
    read a folder only when it is expanded."""
    base = "/" + vpath.replace("\\", "/").strip("/")
    prefix = "" if base == "/" else base
    rec = fs.mft.get(vpath if vpath.strip("/") else "/")
    try:
        listing = rec.listdir()
    except Exception:  # noqa: BLE001 -- unreadable directory index
        listing = {}
    entries = []
    seen = set()
    for name, ie in listing.items():
        ent = _child_entry(name, ie)
        if ent is None or ent["name"] in seen:
            continue
        seen.add(ent["name"])
        ent["path"] = prefix + "/" + ent["name"]
        entries.append(ent)
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return entries


def list_tree(fs, vpath: str, cancel_check=None, _max_nodes: int = 5_000_000):
    """Yield (path, size) for every file anywhere under directory `vpath`, by descending its
    directory index on demand instead of walking the whole MFT. Used to extract a folder the
    user picked in the browse tree. Junctions/symlinks are listed but not followed, and each
    directory record is visited once, so a reparse loop or corrupt tree can't spin forever."""
    stack = [vpath]
    visited = set()
    seen_nodes = 0
    while stack:
        if cancel_check is not None and cancel_check():
            return
        d = stack.pop()
        for ent in list_dir(fs, d):
            seen_nodes += 1
            if seen_nodes > _max_nodes:      # runaway guard on a pathological tree
                return
            if ent["is_dir"]:
                if ent["reparse"] or ent["seg"] in visited:
                    continue
                visited.add(ent["seg"])
                stack.append(ent["path"])
            else:
                yield ent["path"], ent["size"]


def extract_file(fs, volume_path: str, dest_path: str,
                 chunk_size: int = 8 * 1024 * 1024) -> Tuple[int, str]:
    """Copy one file off the volume to a local path. Returns (bytes_written, sha256).
    Read-only against the source."""
    rec = fs.mft.get(volume_path)
    expected = rec.size()
    h = hashlib.sha256()
    written = 0
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with rec.open() as src, open(dest_path, "wb") as out:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)
            h.update(chunk)
            written += len(chunk)
    if written != expected:
        raise IOError(f"short read on {volume_path}: wrote {written:,}, expected {expected:,}")
    return written, h.hexdigest()


def safe_join(dest_dir: str, volume_path: str) -> Optional[str]:
    """Map a path inside the volume to a destination under dest_dir, refusing any path that
    would escape it. The input is untrusted: a crafted or corrupted disk image can carry
    filenames with '..' or absolute components, and a naive join would let an attacker who
    plants a booby-trapped image write files anywhere on the examiner's machine. Returns the
    safe destination path, or None if the path escapes dest_dir and must be skipped."""
    rel = volume_path.replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    # Refuse (rather than silently relocate) anything with a traversal component, so a
    # suspicious path from a crafted image is skipped and logged, not quietly rewritten.
    if not parts or any(p == ".." for p in parts):
        return None
    dest = os.path.join(dest_dir, *parts)
    # Belt-and-suspenders: resolve symlinks too and confirm containment under dest_dir.
    root = os.path.realpath(dest_dir)
    resolved = os.path.realpath(dest)
    if resolved != root and not resolved.startswith(root + os.sep):
        return None
    return dest


def _extract_record(rec, dest_path: str, chunk_size: int = 8 * 1024 * 1024) -> Tuple[int, str]:
    """Copy a file straight from its MFT record to dest_path in bounded chunks. Returns
    (bytes_written, sha256).

    Output is capped at the record's declared size: a corrupted record can claim an absurd
    length, and without the cap the copy loop would write until the examiner's output disk
    fills. A short read (data in an encrypted region) yields a smaller-than-declared file,
    which is honest partial recovery, not an error."""
    expected = rec.size()
    if not isinstance(expected, int) or expected < 0 or expected > MAX_FILE_BYTES:
        raise UnsafeReadRequest(0, expected)          # implausible size => corrupt record
    h = hashlib.sha256()
    written = 0
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    # Write to a temp name and rename on completion, so a process killed mid-copy never leaves
    # a truncated file masquerading as a finished one. A legitimately short recovery (data in
    # an encrypted region) still completes the loop and gets renamed -- that is honest partial
    # recovery, not a failure.
    tmp_path = dest_path + ".scpart"
    with rec.open() as src, open(tmp_path, "wb") as out:
        while written < expected:
            chunk = src.read(min(chunk_size, expected - written))
            if not chunk:
                break
            out.write(chunk)
            h.update(chunk)
            written += len(chunk)
    os.replace(tmp_path, dest_path)
    return written, h.hexdigest()


def extract_all(path: str, base: int, dest_dir: str, min_size: int = 0,
                progress: ProgressFn = None, cancel_check=None, on_file=None,
                only_paths=None) -> List[dict]:
    """Mount the NTFS volume at `base` in `path` and copy every allocated file >= min_size
    out to `dest_dir`, preserving the directory layout. Returns per-file result dicts
    {path, size, written, sha256, error?}. Read-only against the input.

    Enumerate and extract in a single linear pass over the MFT, so a large volume (a full
    OS disk has ~700k records) starts producing files quickly and reports smooth progress,
    instead of stalling for minutes in a recursive directory walk before the first file.
    Destination paths are constrained to stay under dest_dir (see safe_join). `on_file`, if
    given, is called with each per-file result dict as it completes, for streaming callers.
    `only_paths`, if given, is a set of volume paths to restrict extraction to -- used by the
    browse-and-extract-selected flow to pull just the files the user picked."""
    results = []

    def record(r):
        results.append(r)
        if on_file is not None:
            on_file(r)

    with MountedNTFS(path, base) as m:
        total = _total_mft_records(m.fs)
        for idx, seg in _iter_records(m.fs, cancel_check):
            if progress and total and idx % 200 == 0:
                progress(min(idx / total, 0.99), f"Extracting: {len(results):,} files so far")
            got = _file_from_segment(seg, min_size)
            if got is None:
                continue
            vpath, size = got
            if only_paths is not None and vpath not in only_paths:
                continue
            dest = safe_join(dest_dir, vpath)
            if dest is None:
                record({"path": vpath, "size": size,
                        "error": "refused: path escapes the output directory"})
                continue
            try:
                written, sha = _extract_record(seg, dest)
                record({"path": vpath, "size": size, "written": written, "sha256": sha})
            except UnsafeReadRequest as exc:  # corrupt record; recorded, walk continues
                record({"path": vpath, "size": size, "error": f"skipped: {exc}"})
            except Exception as exc:  # noqa: BLE001 -- record and continue with the rest
                record({"path": vpath, "size": size, "error": str(exc)})
        if progress:
            progress(1.0, "Done")
    return results


def extract_selected(path: str, base: int, dest_dir: str, vpaths,
                     progress: ProgressFn = None, cancel_check=None, on_file=None) -> List[dict]:
    """Extract a specific set of files by resolving each path directly in the MFT, instead of
    walking every record. This is what makes "extract the files I picked" near-instant: a
    direct path lookup is O(1), where extract_all's full-MFT scan is minutes on a big disk.
    Returns the same per-file result dicts. Read-only; destinations constrained by safe_join."""
    results = []

    def record(r):
        results.append(r)
        if on_file is not None:
            on_file(r)

    vpaths = list(vpaths)
    total = len(vpaths) or 1
    with MountedNTFS(path, base) as m:
        for i, vpath in enumerate(vpaths):
            if cancel_check is not None and cancel_check():
                break
            if progress:
                progress(min(i / total, 0.99), f"Recovering {i + 1} of {total}")
            dest = safe_join(dest_dir, vpath)
            if dest is None:
                record({"path": vpath, "error": "refused: path escapes the output directory"})
                continue
            try:
                rec = m.fs.mft.get(vpath)
                written, sha = _extract_record(rec, dest)
                record({"path": vpath, "size": rec.size(), "written": written, "sha256": sha})
            except UnsafeReadRequest as exc:
                record({"path": vpath, "error": f"skipped: {exc}"})
            except Exception as exc:  # noqa: BLE001 -- one bad path can't stop the rest
                record({"path": vpath, "error": str(exc)})
        if progress:
            progress(1.0, "Done")
    return results
