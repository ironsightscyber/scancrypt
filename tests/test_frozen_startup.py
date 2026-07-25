"""Regression: a windowed (no-console) frozen build has sys.stderr/stdout = None. Importing
the entry modules must not crash there (faulthandler.enable() would raise 'sys.stderr is
None'). We simulate it by nulling the streams before import in a subprocess.
"""
import subprocess
import sys

import pytest


def _import_returncode(module, null_streams: bool) -> int:
    pre = "import sys; sys.stderr = None; sys.stdout = None; " if null_streams else ""
    return subprocess.run([sys.executable, "-c", pre + f"import {module}"]).returncode


def test_cli_imports_without_stderr():
    # rprt.cli has no GUI dependency, so this always runs.
    assert _import_returncode("rprt.cli", null_streams=True) == 0


def test_gui_imports_without_stderr():
    # rprt.gui pulls in PySide6, which may not import on a headless CI runner (missing GL
    # libs) for reasons unrelated to the faulthandler guard. Only assert the regression --
    # that nulling the streams does not make import fail -- when it imports cleanly at all.
    if _import_returncode("rprt.gui", null_streams=False) != 0:
        pytest.skip("rprt.gui (PySide6) not importable in this environment")
    assert _import_returncode("rprt.gui", null_streams=True) == 0
