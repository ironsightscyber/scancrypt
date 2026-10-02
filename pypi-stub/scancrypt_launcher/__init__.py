"""ScanCrypt is distributed as a signed Windows application, not as a Python package.

This stub exists so that `pip install scancrypt` and anyone with an older pip install of
ScanCrypt is directed to the official signed download rather than silently getting nothing.
"""
import webbrowser

DOWNLOAD_URL = "https://github.com/ironsightscyber/scancrypt/releases/latest"

MESSAGE = f"""
ScanCrypt is now distributed as a signed Windows application.

It is no longer installed from PyPI. Download the latest signed release here:

    {DOWNLOAD_URL}

Both the GUI (scancrypt-gui.exe) and the command-line tool (scancrypt.exe) are available
there, code-signed by IronSights.
"""


def notice():
    print(MESSAGE)
    try:
        webbrowser.open(DOWNLOAD_URL)
    except Exception:
        pass


if __name__ == "__main__":
    notice()
