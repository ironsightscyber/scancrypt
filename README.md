# ScanCrypt

**ScanCrypt finds and extracts the parts of a ransomware-encrypted file that were never actually encrypted.**

Most ransomware does not encrypt entire files. To work fast across a whole disk it
encrypts the start of each file, or strips of it at a fixed interval, and leaves the rest
as plaintext. ScanCrypt measures exactly which bytes are ciphertext and which are not,
then carves out the recoverable plaintext so you can triage what is salvageable before you
decide whether to pay, restore, or rebuild.

ScanCrypt is a product of [IronSights](https://ironsights.com.au). It is distributed as a
signed Windows application. Source code is not public.

---

## Download

Get the latest signed release from the [Releases page](../../releases/latest).

| File | What it is |
|------|-----------|
| `scancrypt-gui.exe` | The graphical application. Start here. |
| `scancrypt.exe` | Command-line version, for scripting and batch triage. |
| `scancrypt-macos.zip` | The macOS application bundle (ScanCrypt.app), Apple silicon. |
| `*.sha256` | Checksums for verifying your download. |

Both Windows executables are code-signed by IronSights (DigiCert OV certificate). Windows will show
**IronSights** as the verified publisher in the User Account Control prompt. The macOS bundle is
not yet code-signed: right-click ScanCrypt.app and choose **Open** on first launch.

## Verify your download

Confirm the file matches its published checksum before running it:

```powershell
Get-FileHash .\scancrypt-gui.exe -Algorithm SHA256
# Compare the output against the contents of scancrypt-gui.exe.sha256
```

And confirm the Authenticode signature:

```powershell
Get-AuthenticodeSignature .\scancrypt-gui.exe | Format-List Status, SignerCertificate
# Status should be "Valid" and the signer should be IronSights.
```

## Requirements

- Windows 10 or 11, 64-bit.
- macOS on Apple silicon, for the app bundle.
- No Python install required. Everything is bundled in the executable.

## Using it on a ransomware incident

Work from a copy, never the original evidence. Image the affected disk or copy the files
to separate storage first, then point ScanCrypt at the copy. ScanCrypt only ever reads
your data; it does not modify the files it scans.

## Support

- **Issues and bug reports:** open an issue on this repository.
- **Security and incident response:** team@scancrypt.org
- **Commercial enquiries:** https://ironsights.com.au

## Licence

ScanCrypt is proprietary software. Your use of the downloaded binaries is governed by the
[End User Licence Agreement](EULA.txt). The source code is not distributed.
