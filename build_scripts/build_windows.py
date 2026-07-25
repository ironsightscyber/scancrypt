"""
Build a single-file Windows .exe of the GUI with PyInstaller.

Run this ON WINDOWS (PyInstaller does not cross-compile):
    python -m venv .venv
    .venv\\Scripts\\activate
    pip install -e .[dev]
    python build_scripts\\build_windows.py

Output: dist\\scancrypt-gui.exe
"""
import os
import PyInstaller.__main__

from versioninfo import write_version_file

VERSION_FILE = write_version_file(
    "build_scripts/_version_gui.txt",
    "ScanCrypt ransomware partial-recovery tool")

PyInstaller.__main__.run([
    "build_scripts/entry_gui.py",   # launcher: absolute import, avoids relative-import crash
    "--name=scancrypt-gui",
    "--paths=src",
    "--onefile",
    "--windowed",
    "--noconfirm",
    "--icon=assets/scancrypt.ico",
    "--version-file=" + VERSION_FILE,
    # the signature table is data loaded at runtime; bundle it next to the package
    "--add-data=" + "src/rprt/signatures.yaml" + os.pathsep + "rprt",
    # ship the icon too so the running app can use it as its window icon
    "--add-data=" + "assets/scancrypt.ico" + os.pathsep + "assets",
    # dissect.ntfs (optional NTFS extraction) is imported lazily, so PyInstaller's static
    # graph misses its submodules -- pull them in explicitly so the exe ships with it.
    "--collect-submodules=dissect",
])
