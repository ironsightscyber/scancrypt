"""Allow `python -m rprt ...` to run the CLI. Used in development by the process supervisor
to spawn the recovery worker; the frozen build spawns scancrypt.exe instead."""
import sys

from rprt.cli import main

if __name__ == "__main__":
    sys.exit(main())
