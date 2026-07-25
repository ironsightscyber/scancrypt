"""
Build a macOS .app bundle of the ScanCrypt GUI with PyInstaller.

Run this ON macOS (PyInstaller does not cross-compile):
    python -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"
    python build_scripts/make_icon.py       # produces assets/scancrypt.icns
    python build_scripts/build_macos.py

Output: dist/ScanCrypt.app  (zip it for distribution: `ditto -c -k --keepParent dist/ScanCrypt.app dist/scancrypt-macos.zip`)

The Mac build covers scanning files, disk images, and virtual disks (VHDX/VHD/VMDK) and
extracting from them. Raw-device scanning and the admin banner are Windows-only and stay
inert on macOS. The bundle is unsigned, so Gatekeeper will block the first launch: users
right-click the app and choose Open, or run `xattr -dr com.apple.quarantine ScanCrypt.app`.
"""
import os
import PyInstaller.__main__

args = [
    "build_scripts/entry_gui.py",   # launcher: absolute import, avoids relative-import crash
    "--name=ScanCrypt",
    "--paths=src",
    "--windowed",                   # .app bundle, no console
    "--noconfirm",
    "--osx-bundle-identifier=au.com.ironsights.scancrypt",
    "--add-data=" + "src/rprt/signatures.yaml" + os.pathsep + "rprt",
    "--collect-submodules=dissect",
]
if os.path.exists("assets/scancrypt.icns"):
    args.append("--icon=assets/scancrypt.icns")

PyInstaller.__main__.run(args)
