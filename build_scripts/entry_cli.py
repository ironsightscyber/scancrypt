"""PyInstaller entry point for the CLI exe.

PyInstaller runs the entry script as __main__ with no package context, so the package's
own relative imports (from . import engine) would fail if we pointed it straight at
cli.py. This launcher uses an absolute import instead, and pulls the whole rprt package
into the frozen build.
"""
import sys

from rprt.cli import main

if __name__ == "__main__":
    sys.exit(main())
