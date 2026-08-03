"""CLI failure paths must read like advice, not like a crash.

Someone reaching for this is mid-incident. The documented raw-disk scan needs Administrator,
and forgetting to elevate is the obvious mistake -- but it used to surface as an uncaught
PermissionError plus PyInstaller's "Failed to execute script 'entry_cli' due to unhandled
exception!", which reads as a broken tool rather than a missing right-click.
"""
import builtins

import pytest

from rprt import cli, source


def _force_raw(monkeypatch):
    """Treat the path as a raw device regardless of host OS, so these run on Linux CI too
    (is_raw_device is win32-only, and would otherwise short-circuit every case here)."""
    monkeypatch.setattr(source, "is_raw_device", lambda p: True)


def _open_raises(monkeypatch, exc):
    real_open = builtins.open

    def fake_open(path, *a, **k):
        if str(path).startswith("\\\\.\\"):
            raise exc
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)


def test_raw_device_without_admin_explains_how_to_elevate(monkeypatch):
    _force_raw(monkeypatch)
    _open_raises(monkeypatch, PermissionError(13, "Permission denied"))

    msg = cli._raw_device_problem(r"\\.\C:")

    assert msg is not None
    assert "Administrator" in msg
    assert "Run as administrator" in msg
    # and it should say what still works without elevating, so the user has a next step
    assert "disk image" in msg
    assert "Traceback" not in msg


def test_missing_raw_device_names_the_alternatives(monkeypatch):
    _force_raw(monkeypatch)
    _open_raises(monkeypatch, FileNotFoundError(2, "No such file or directory"))

    msg = cli._raw_device_problem(r"\\.\PhysicalDrive99")

    assert msg is not None
    assert "no such device" in msg
    assert "PhysicalDrive0" in msg
    assert "Traceback" not in msg


def test_other_os_error_is_still_reported_cleanly(monkeypatch):
    _force_raw(monkeypatch)
    _open_raises(monkeypatch, OSError(5, "I/O error"))

    msg = cli._raw_device_problem(r"\\.\PhysicalDrive0")

    assert msg is not None and msg.startswith("error: cannot open")


def test_readable_raw_device_reports_no_problem(monkeypatch, tmp_path):
    """A device that opens must not be rejected -- the guard only reports failures."""
    _force_raw(monkeypatch)
    real = tmp_path / "stand_in_device.img"
    real.write_bytes(b"\x00" * 4096)

    assert cli._raw_device_problem(str(real)) is None


def test_ordinary_file_path_is_never_treated_as_a_device(tmp_path):
    """Without the raw-device prefix the guard must stay out of the way entirely."""
    p = tmp_path / "evidence.img"
    p.write_bytes(b"\x00" * 4096)

    assert cli._raw_device_problem(str(p)) is None


def test_help_uses_the_shipped_command_name(capsys):
    """`scancrypt --help` printed `usage: rprt`, the pre-rename internal name."""
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert capsys.readouterr().out.startswith("usage: scancrypt")
