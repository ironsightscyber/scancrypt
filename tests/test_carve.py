"""PhotoRec orchestration.

PhotoRec isn't installed in CI, so the real binary is replaced by a stub script that
mimics its contract: parse `/d <prefix>`, create <prefix>.1 with a couple of files, print
progress lines, exit 0. Pointing RPRT_PHOTOREC at the stub exercises the whole carve()
path -- command construction, invocation, streaming, and result collection -- for real.
"""
import os
import random
import stat
import sys

import pytest

from rprt import carve, engine


def _write_stub(tmp_path):
    """A fake photorec: reads its argv, creates <dest_prefix>.1 with fake recovered files."""
    stub = tmp_path / "photorec_stub.py"
    stub.write_text(
        "import os, sys\n"
        "argv = sys.argv[1:]\n"
        "dest = argv[argv.index('/d') + 1]\n"
        "d = dest + '.1'\n"
        "os.makedirs(d, exist_ok=True)\n"
        "open(os.path.join(d, 'f0001.jpg'), 'wb').write(b'JPEGDATA' * 100)\n"
        "open(os.path.join(d, 'f0002.pdf'), 'wb').write(b'%PDF-1.4' * 50)\n"
        "open(os.path.join(d, 'report.xml'), 'w').write('<report/>')\n"
        "print('PhotoRec 7.2, Pass 1')\n"
        "print('recovered 2 files')\n"
    )
    launcher = tmp_path / ("photorec" + (".bat" if os.name == "nt" else ""))
    if os.name == "nt":
        launcher.write_text(f'@echo off\r\n"{sys.executable}" "{stub}" %*\r\n')
    else:
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{stub}" "$@"\n')
        launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(launcher)


@pytest.fixture
def stub_photorec(tmp_path, monkeypatch):
    launcher = _write_stub(tmp_path)
    monkeypatch.setenv("RPRT_PHOTOREC", launcher)
    return launcher


def test_build_command_default_all_types():
    cmd = carve.build_command("photorec", "img.bin", "/out/recup_dir")
    assert cmd[0] == "photorec"
    assert "/d" in cmd and cmd[cmd.index("/d") + 1] == "/out/recup_dir"
    assert cmd[-1] == "partition_none,wholespace,search"
    assert cmd[cmd.index("/cmd") + 1] == "img.bin"


def test_build_command_file_types_and_freespace():
    cmd = carve.build_command("photorec", "img.bin", "/out/recup_dir",
                              whole_space=False, file_types=["jpg", "pdf"])
    chain = cmd[-1]
    assert chain.startswith("partition_none,options,fileopt,everything,disable,")
    assert "jpg,enable" in chain and "pdf,enable" in chain
    assert chain.endswith("freespace,search")


def test_find_photorec_env_override(stub_photorec):
    assert carve.available()
    assert carve.find_photorec() == stub_photorec


def test_collect_recovered_summarises(tmp_path):
    prefix = tmp_path / "recup_dir"
    d = tmp_path / "recup_dir.1"
    d.mkdir()
    (d / "a.jpg").write_bytes(b"x" * 10)
    (d / "b.jpg").write_bytes(b"y" * 20)
    (d / "c.pdf").write_bytes(b"z" * 30)
    (d / "report.xml").write_text("<r/>")   # must be ignored
    summary = carve.collect_recovered(str(prefix))
    assert summary["file_count"] == 3
    assert summary["total_bytes"] == 60
    assert summary["by_extension"] == {"jpg": 2, "pdf": 1}


def test_carve_end_to_end_with_stub(stub_photorec, tmp_path):
    image = tmp_path / "img.bin"
    image.write_bytes(b"\x00" * 1024)
    out = tmp_path / "carved"
    lines = []
    summary = carve.carve(str(image), str(out), log=lines.append)
    assert summary["returncode"] == 0
    assert summary["file_count"] == 2
    assert summary["by_extension"] == {"jpg": 1, "pdf": 1}
    assert any("Pass 1" in ln for ln in lines)


def test_carve_recoverable_isolates_intact_region(stub_photorec, tmp_path):
    # front-only file: intact region is isolated to a temp file, carved, then removed
    rng = random.Random(1)
    enc = bytes(rng.getrandbits(8) for _ in range(2 * 1024 * 1024))
    body = (b"plain text " * 100000)[:6 * 1024 * 1024]
    p = tmp_path / "s.bin"
    p.write_bytes(enc + body)
    report = engine.scan(str(p))
    assert report.pattern == "front-only"

    out = tmp_path / "carved"
    summary = carve.carve_recoverable(str(p), report, str(out), isolate_intact=True)
    assert summary["file_count"] == 2
    # the intermediate intact-region file is cleaned up by default
    assert not os.path.exists(os.path.join(str(out), "_intact_region.bin"))


def test_carve_recoverable_refuses_fully_encrypted(tmp_path):
    rng = random.Random(2)
    p = tmp_path / "f.bin"
    p.write_bytes(bytes(rng.getrandbits(8) for _ in range(2 * 1024 * 1024)))
    report = engine.scan(str(p))
    assert report.pattern == "fully-encrypted"
    with pytest.raises(ValueError):
        carve.carve_recoverable(str(p), report, str(tmp_path / "c"))


def test_carve_raises_without_photorec(monkeypatch, tmp_path):
    monkeypatch.delenv("RPRT_PHOTOREC", raising=False)
    monkeypatch.setattr(carve.shutil, "which", lambda *_: None)
    monkeypatch.setattr(carve.os.path, "isfile", lambda *_: False)
    assert not carve.available()
    with pytest.raises(RuntimeError):
        carve.carve(str(tmp_path / "x.bin"), str(tmp_path / "o"))
