"""rprt.formats — container/format detection on the intact region (v0.2).

Once a scan knows which bytes survived, recognising *what* the file is turns a blind
byte carve into a structure-aware recovery: a VHDX/VMDK disk image wants filesystem
extraction, a SQL MDF wants page-level carving, a ZIP/OOXML/PST wants its own reader.

Two detection angles, because ransomware usually destroys the front:
  - header signatures at offset 0 (useful when the front survived, i.e. fully-intact or
    a file whose header sits past the encrypted region), and
  - interior signatures scanned across the intact region -- e.g. an NTFS boot sector or
    SQL Server pages -- which survive even when the container's own header was encrypted.
    This is exactly why a fixed VHDX whose header was destroyed is still recoverable: the
    NTFS volume inside it is intact and self-identifying.

Detection is read-only and best-effort; it never fails a scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .source import open_source


@dataclass(frozen=True)
class HeaderSig:
    name: str
    magic: bytes
    offset: int = 0
    extraction_hint: str = ""
    # True for formats whose payload is compressed by definition (archives, compressed
    # streams). A valid one of these at the start of the intact region proves the region's
    # high entropy is compression, not encryption -- the rigorous answer where the
    # chi-square test can't help (e.g. LZMA/xz, which is statistically uniform).
    compressed_container: bool = False


@dataclass(frozen=True)
class InteriorSig:
    name: str
    magic: bytes
    # magic sits at this offset within each aligned unit (e.g. NTFS boot sector: "NTFS"
    # at byte 3 of a volume; SQL page header pattern within an 8192-byte page).
    within_offset: int
    extraction_hint: str = ""


# Header magics checked at a fixed file offset (front-survived case).
HEADER_SIGS = [
    HeaderSig("VHDX disk image", b"vhdxfile", 0,
              "Fixed-VHDX payload begins at a known fixed offset; parse the filesystem "
              "inside directly rather than repairing the container."),
    HeaderSig("VMDK disk image", b"KDMV", 0, "VMware sparse disk; parse the embedded filesystem."),
    HeaderSig("VMDK descriptor", b"# Disk DescriptorFile", 0, "VMware descriptor; locate the extent files."),
    HeaderSig("ZIP / OOXML / (docx,xlsx,pptx)", b"PK\x03\x04", 0,
              "Hand the intact range to a ZIP-aware carver.", compressed_container=True),
    HeaderSig("PST / OST mailbox", b"!BDN", 0, "Use a PST-aware reader on the intact range."),
    HeaderSig("PDF document", b"%PDF-", 0, "Carve as a single PDF object stream."),
    HeaderSig("SQLite database", b"SQLite format 3\x00", 0, "Open read-only with SQLite; check integrity."),
    HeaderSig("7-Zip archive", b"7z\xbc\xaf\x27\x1c", 0,
              "Extract with a 7z-aware carver.", compressed_container=True),
    HeaderSig("RAR archive", b"Rar!\x1a\x07", 0,
              "Extract with a RAR-aware carver.", compressed_container=True),
    HeaderSig("xz / LZMA2 stream", b"\xfd7zXZ\x00", 0,
              "Decompress with xz/lzma.", compressed_container=True),
    HeaderSig("gzip stream", b"\x1f\x8b\x08", 0,
              "Decompress with gzip.", compressed_container=True),
    HeaderSig("bzip2 stream", b"BZh", 0,
              "Decompress with bzip2.", compressed_container=True),
    HeaderSig("zstandard stream", b"\x28\xb5\x2f\xfd", 0,
              "Decompress with zstd.", compressed_container=True),
    HeaderSig("ESE / ntds.dit / EDB", b"\xef\xcd\xab\x89", 4, "Jet/ESE database; use an ESE reader."),
]

# Interior signatures scanned across the intact region (header-destroyed case). Only
# strong, low-false-positive magics belong here -- an 8-byte OEM/type string at a fixed
# sector offset. Weaker structures (e.g. SQL Server MDF pages, identifiable only by a
# page-id-matches-offset check across many pages) are left to a dedicated validator
# (prototypes/sql_page_validate.py), not a magic scan.
INTERIOR_SIGS = [
    InteriorSig("NTFS filesystem (boot sector)", b"NTFS    ", 3,
                "Intact NTFS volume found -- mount it at this offset and copy files out "
                "(see prototypes/ntfs_reader.py); no need to repair the container header."),
    InteriorSig("FAT32 filesystem", b"FAT32   ", 82, "Intact FAT32 volume; mount at this offset."),
]

SCAN_WINDOW = 4 * 1024 * 1024   # bytes of the intact region to search for interior sigs
NTFS_ALIGN = 512                # NTFS/FAT boot sectors sit on 512-byte sector boundaries


@dataclass
class FormatFinding:
    name: str
    where: str          # "header" | "interior"
    offset: int         # byte offset in the file where the signature matched
    extraction_hint: str

    def to_dict(self) -> dict:
        return {"name": self.name, "where": self.where, "offset": self.offset,
                "extraction_hint": self.extraction_hint}


def _check_headers(src, intact_start: int) -> List[FormatFinding]:
    findings = []
    # Read enough to cover the largest header offset + magic.
    head = src.read_at(intact_start, 512)
    for sig in HEADER_SIGS:
        end = sig.offset + len(sig.magic)
        if len(head) >= end and head[sig.offset:end] == sig.magic:
            findings.append(FormatFinding(sig.name, "header", intact_start + sig.offset,
                                          sig.extraction_hint))
    return findings


def _check_interior(src, intact_start: int, intact_end: int) -> List[FormatFinding]:
    findings = []
    seen = set()
    window = min(SCAN_WINDOW, max(intact_end - intact_start, 0))
    if window <= 0:
        return findings
    data = src.read_at(intact_start, window)

    # Boot sectors / page headers sit at a fixed offset within a 512-byte-aligned unit;
    # scan sector-aligned positions and report the first match per signature.
    for sig in INTERIOR_SIGS:
        limit = len(data) - (sig.within_offset + len(sig.magic))
        pos = 0
        while pos <= limit:
            start = pos + sig.within_offset
            if data[start: start + len(sig.magic)] == sig.magic:
                off = intact_start + pos
                if (sig.name, off) not in seen:
                    seen.add((sig.name, off))
                    findings.append(FormatFinding(sig.name, "interior", off, sig.extraction_hint))
                break
            pos += NTFS_ALIGN
    return findings


def detect(path: str, intact_start: int = 0, intact_end: Optional[int] = None) -> List[dict]:
    """Detect container/file formats in the intact region [intact_start, intact_end).

    intact_start is typically the scan's boundary_offset (start of recoverable bytes);
    intact_end defaults to end of file. Returns a list of finding dicts, header matches
    first. Best-effort: any read error yields an empty list rather than raising.
    """
    try:
        with open_source(path) as src:
            if intact_end is None:
                intact_end = src.size
            findings = _check_headers(src, intact_start)
            findings += _check_interior(src, intact_start, intact_end)
            return [f.to_dict() for f in findings]
    except Exception:  # noqa: BLE001 -- detection is advisory, never fatal
        return []


def compressed_container_at(path: str, offset: int = 0) -> Optional[str]:
    """If the bytes at `offset` are the header of a compressed archive/stream (ZIP, 7z,
    RAR, xz, gzip, bzip2, zstd), return the format name, else None.

    A valid header here is proof the region is compressed, not encrypted -- and since
    ransomware encrypting the front destroys the header, a present header also means the
    front was not encrypted. This is the rigorous fallback for compressors whose output is
    statistically uniform (LZMA/xz), which the chi-square test cannot flag. Only checks the
    exact offset (no scan), so a coincidental match on random data is astronomically
    unlikely for these multi-byte magics.
    """
    try:
        with open_source(path) as src:
            head = src.read_at(offset, 16)
    except Exception:  # noqa: BLE001
        return None
    for sig in HEADER_SIGS:
        if not sig.compressed_container or sig.offset != 0:
            continue
        if head[:len(sig.magic)] == sig.magic:
            return sig.name
    return None
