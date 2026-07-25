"""
Build the slim, portable ScanCrypt command-line exe (no GUI).

This is the build to hand out and carry on a USB stick: it drops PySide6/Qt entirely,
which is most of the weight in the full GUI build, and produces a single console exe that
runs on a locked-down Windows box with nothing installed. The standalone HTML report is the
user interface, so no GUI toolkit is needed.

Run on Windows (PyInstaller does not cross-compile):
    python -m venv .venv
    .venv\\Scripts\\activate
    pip install -e ".[dev]"
    python build_scripts\\build_cli.py

Output: dist\\scancrypt.exe

Note on antivirus: any PyInstaller exe can trip heuristic AV flags. A slim, simple build
trips fewer, but the durable fix is a native binary. See the project README.
"""
import os
import PyInstaller.__main__

from versioninfo import write_version_file

# PyInstaller's --add-data uses the OS path separator (';' on Windows, ':' elsewhere).
SIG_DATA = "src/rprt/signatures.yaml" + os.pathsep + "rprt"

VERSION_FILE = write_version_file(
    "build_scripts/_version_cli.txt",
    "ScanCrypt command-line ransomware partial-recovery scanner")

PyInstaller.__main__.run([
    "build_scripts/entry_cli.py",   # launcher: absolute import, avoids relative-import crash
    "--name=scancrypt",
    "--paths=src",
    "--onefile",
    "--console",
    "--noconfirm",
    "--icon=assets/scancrypt.ico",
    "--version-file=" + VERSION_FILE,
    # keep the GUI toolkit out of the CLI build entirely
    "--exclude-module=PySide6",
    "--exclude-module=shiboken6",
    # the signature table is data loaded at runtime; bundle it next to the package
    "--add-data=" + SIG_DATA,
    # dissect.ntfs is imported lazily for volume extraction; pull its submodules in
    "--collect-submodules=dissect",
])
