"""
Generate the Windows version resource PyInstaller embeds in the exes.

Unsigned exes with no version metadata are a classic trigger for Defender's ML
heuristics (Wacatac-style false positives), and SignPath's OSS program requires the
product name and version to be set. Writing the file at build time keeps the numbers
in lockstep with rprt.__version__ instead of hand-maintaining a copy.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from rprt import __version__  # noqa: E402


def write_version_file(out_path: str, exe_description: str) -> str:
    parts = (__version__.split(".") + ["0", "0", "0"])[:3]
    nums = ", ".join(parts) + ", 0"
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({nums}),
    prodvers=({nums}),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'IronSights Pty Ltd'),
      StringStruct('FileDescription', '{exe_description}'),
      StringStruct('FileVersion', '{__version__}'),
      StringStruct('ProductName', 'ScanCrypt'),
      StringStruct('ProductVersion', '{__version__}'),
      StringStruct('LegalCopyright', 'Copyright 2026 IronSights Pty Ltd. Apache License 2.0.'),
      StringStruct('Comments', 'Free open-source ransomware partial-recovery tool. https://scancrypt.org')
    ])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return out_path
