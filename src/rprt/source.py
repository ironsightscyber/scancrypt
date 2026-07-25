"""rprt.source — read-only input abstraction over regular files and raw Windows devices.

The engine scans two kinds of input:
  - regular files / disk-image files (any OS), and
  - raw Windows block devices (``\\\\.\\PhysicalDrive1``, ``\\\\.\\D:``) so an incident
    responder can scan a disk in place without imaging 100+ GB first.

Raw device handles differ from files in two ways this module hides from the engine:
  - ``os.path.getsize`` / ``seek(0, 2)`` don't report a usable size, so the length is
    queried with ``IOCTL_DISK_GET_LENGTH_INFO``;
  - reads must be sector-aligned (offset AND length), so arbitrary-offset reads are
    satisfied by reading the enclosing aligned range and slicing.

Everything here opens inputs strictly read-only.
"""
from __future__ import annotations

import os
import sys

# Align raw-device reads to 4096 bytes: a multiple of both 512e and 4Kn sector sizes,
# so it satisfies the alignment requirement on either kind of drive.
RAW_ALIGN = 4096


def is_raw_device(path: str) -> bool:
    return sys.platform == "win32" and path.startswith("\\\\.\\")


def is_scannable(path: str) -> bool:
    return os.path.isfile(path) or is_raw_device(path)


def aligned_read(f, total_size: int, offset: int, length: int, align: int) -> bytes:
    """Read ``length`` bytes at ``offset`` from a handle that only accepts
    align-multiple seeks/reads, by reading the enclosing aligned range and slicing.
    Clamps to ``total_size`` so a read near the end of the device never asks the
    kernel for bytes past the last sector."""
    if offset >= total_size or length <= 0:
        return b""
    end = min(offset + length, total_size)
    a_start = (offset // align) * align
    a_end = min(-(-end // align) * align, (total_size // align) * align)
    if a_end <= a_start:
        return b""
    f.seek(a_start)
    buf = f.read(a_end - a_start)
    return buf[offset - a_start: offset - a_start + (end - offset)]


class FileSource:
    """A regular file or disk-image file."""

    def __init__(self, path: str):
        self.path = path
        self.size = os.path.getsize(path)
        self._f = open(path, "rb")

    def read_at(self, offset: int, length: int) -> bytes:
        self._f.seek(offset)
        return self._f.read(length)

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class RawDeviceSource:
    """A raw Windows block device (``\\\\.\\PhysicalDriveN`` or ``\\\\.\\X:``).

    Requires Administrator rights to open. Read-only: opened with ``rb`` and never
    written. Size comes from ``IOCTL_DISK_GET_LENGTH_INFO``, which works for both
    physical drives and logical volumes.

    Known limitation: reads are aligned to 4096 bytes, so on a 512-byte-sector volume
    whose length is not a 4096 multiple, the final partial 4 KiB tail is treated as
    unreadable and clamped off. At most ~3.5 KiB at the very end of a volume -- of no
    consequence for entropy triage of multi-GB inputs.
    """

    IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

    def __init__(self, path: str):
        self.path = path
        # buffering=0: our own alignment handling assumes reads map 1:1 to the device.
        self._f = open(path, "rb", buffering=0)
        self.size = self._query_length()

    def _query_length(self) -> int:
        import ctypes
        import ctypes.wintypes as wt
        import msvcrt

        handle = msvcrt.get_osfhandle(self._f.fileno())
        out = ctypes.c_int64(0)
        returned = wt.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            wt.HANDLE(handle), wt.DWORD(self.IOCTL_DISK_GET_LENGTH_INFO),
            None, 0,
            ctypes.byref(out), ctypes.sizeof(out),
            ctypes.byref(returned), None,
        )
        if not ok:
            err = ctypes.GetLastError()
            raise OSError(
                f"IOCTL_DISK_GET_LENGTH_INFO failed on {self.path} "
                f"(WinError {err}). Raw device scans require running as Administrator."
            )
        return out.value

    def read_at(self, offset: int, length: int) -> bytes:
        return aligned_read(self._f, self.size, offset, length, RAW_ALIGN)

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def open_source(path: str):
    """Open a scan input read-only: raw device path on Windows, regular file otherwise."""
    if is_raw_device(path):
        return RawDeviceSource(path)
    return FileSource(path)
