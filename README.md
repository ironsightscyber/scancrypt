# ScanCrypt — get back the data the ransomware never touched

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/ironsightscyber/scancrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/ironsightscyber/scancrypt/actions)

Most ransomware is in a race: encrypting terabytes takes hours, so to finish before
it's caught it only scrambles **part** of each large file — the first chunk, or stripes
through it — then renames it so everything *looks* equally dead. It usually isn't.

**ScanCrypt** scans an encrypted file or disk, measures exactly which bytes were never
actually encrypted, and pulls those bytes back out — **no decryption key, no ransom.**
It is not a decryptor; it's a ransomware-aware *partial-recovery* tool. Databases, VM
disks, and backup archives are typically **mostly intact** underneath.

Free and open source (Apache-2.0), **read-only**, by [IronSights](https://ironsights.com.au) ·
[scancrypt.org](https://scancrypt.org) · [Plain-English guide for victims](docs/recover.html)

> **Honest by design.** Recoverability is always reported as *most, not all*, with the
> measured percentage. A partial file list is flagged as partial, never passed off as
> complete. Family IDs are labelled *validated* vs *from public reporting*. Fully-encrypted
> and small files are out of scope. Provided AS IS, no warranty; use only on systems you
> are authorised to examine.

---

## Install

**Just want to run it?** Download the app from the
[releases page](https://github.com/ironsightscyber/scancrypt/releases/latest) —
`scancrypt-gui.exe` (Windows) is a single portable file, nothing to install, fully offline.
No terminal needed. New to this? Read the [plain-English guide](docs/recover.html).

**From source (any OS):**

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[ntfs]"             # ".[ntfs]" adds VHDX/VHD/VMDK + NTFS support
scancrypt --help                     # or:  python -m rprt --help
```

`dissect.hypervisor` + `dissect.ntfs` (pulled in by `[ntfs]`) are what let ScanCrypt read
files out of a virtual disk. Everything else works without them.

---

## Quickstart

### 1. How much of a file/disk is recoverable?

```bash
scancrypt "SQL_DATA_D.vhdx"
```

```
size        108.5 GB
pattern     front-only
recoverable 100.0%
encrypted   0.0002%   258 KB at the front
family      Makop / Phobos  (validated)
```

Add `--report triage.html` for a shareable HTML report, `--json out.json` for machine output.
Scans stay fast **even on huge disks** — a 322 GB VM images in seconds, because finding the
encryption boundary doesn't require reading the whole file.

### 2. Recover files from a virtual disk (the headline workflow)

Ransomware often encrypts a VM disk's header, so it won't mount. ScanCrypt rebuilds the disk
from the block map that survived and reads the files straight out — names and folders intact.

```bash
scancrypt "SQL_DATA_D.vhdx" --list-volume            # see what's inside
scancrypt "SQL_DATA_D.vhdx" --recover-files ./out    # copy the files out
```

Recover only specific files (near-instant, no full walk):

```bash
printf '/Program Files/.../DATA/production.mdf\n' > paths.txt
scancrypt "SQL_DATA_D.vhdx" --recover-files ./out --only-paths paths.txt
```

If part of the disk didn't survive, the file list says so (`… (partial)`) instead of
pretending it's complete.

### 3. Check a recovered SQL Server database

```bash
scancrypt recovered.mdf --validate-sql
```

```
253,478 valid SQL Server page(s)  (90.6%)   verdict: sql-data-present
database name: production_db
```

A page-level integrity check (a structural analogue to DBCC), so you know what you got back
before handing it to a DBA.

### 4. Triage a whole share at once

```bash
scancrypt /mnt/encrypted_share --report incident.html --csv incident.csv
```

One incident-wide figure — *"across N files totalling X TB, this fraction is recoverable for
free"* — with a per-file breakdown for a client or insurer.

### 5. Extract the intact bytes of a single large file

```bash
scancrypt victim.bin --extract recovered.bin
```

---

## Common options

| Flag | What it does |
|------|--------------|
| `--report FILE` | standalone HTML triage report (add `--hash` to embed a SHA-256) |
| `--json FILE` | full machine-readable report |
| `--list-volume` | list every file in a virtual disk's NTFS volume |
| `--recover-files DIR` | recover files from a VHDX/VHD/VMDK (rebuilds an encrypted-header disk) |
| `--only-paths FILE` | with `--recover-files`, restrict to listed paths |
| `--validate-sql` | page-level check of a recovered SQL Server MDF/NDF |
| `--fingerprint` | emit a privacy-safe family signature stub + pre-filled issue link (no file contents) |
| `--extract FILE` | write the intact byte ranges of a single file |
| `--carve DIR` | carve loose files from the recoverable region (needs PhotoRec) |
| `--boundary-only` | accept the fast front-boundary result; never do a full-disk read |
| `--full` | force a full block-by-block scan (precise map, reads the whole file) |
| `--audit-log FILE` | hash-chained, tamper-evident audit trail (+ `--case-id`, `--examiner`, `--evidence-id`) |

Scan a raw disk in place (Windows, elevated prompt): `scancrypt \\.\PhysicalDrive1 --json triage.json`

Evidence-grade run and later verification:

```bash
scancrypt disk.img --extract out.bin --audit-log audit.jsonl \
    --case-id CASE-0001 --examiner "A. Analyst" --evidence-id DISK-01
python -c "from rprt import forensics; print(forensics.verify_log('audit.jsonl'))"
```

---

## How it works (four read-only stages)

1. **Map the encryption.** An entropy scan brackets where the encryption starts and stops,
   then binary-searches down to the byte. It stays cheap on huge disks and only escalates to
   a full read when the evidence points to a genuine second encrypted region — not to the
   scattered high-entropy blocks (databases, compressed content) that are normal on any disk.
2. **Tell ciphertext from compression.** Encrypted and compressed data both look random; a
   chi-square test plus archive-header checks separate real ciphertext from an ordinary zip,
   image, or database blob, so recoverable data isn't written off.
3. **Report the number.** A recoverable percentage, an entropy map, the strain, and the
   limits stated plainly — per file, or rolled up across a whole share.
4. **Recover.** Extract intact byte ranges; pull files out of a virtual disk (even one whose
   header was destroyed); validate a recovered SQL database; carve loose files. Hashes are
   recorded throughout.

Recovery is **family-agnostic** — a wrong or unknown family guess never affects what comes
back; identification only names the strain and sets expectations. Validated families
(matched against real samples) vs public-reporting-only ones are labelled as such.

---

## Honest limits

- Not decryption — it recovers bytes that were never encrypted; the rest stays locked.
- Recovery is *most, not all*; the report gives a measured figure, not a promise every file opens.
- Small files are usually encrypted end-to-end. The value is in big files: databases, VM disks, backups, media.
- Periodic/intermittent patterns recover less cleanly than front-only.
- No warranty, no liability. Authorised systems only.

---

## For developers

### Dev setup

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Run the GUI locally (works on macOS/Linux for development): `python -m rprt.gui`

### Build the Windows app

Must run on Windows (PyInstaller doesn't cross-compile):

```powershell
python -m venv .venv; .venv\Scripts\activate
pip install -e ".[dev]"
python build_scripts\build_windows.py     # -> dist\rprt-gui.exe (single file, no installer)
```

CI runs the suite on Ubuntu + Windows on every push and builds `rprt-gui.exe`; pushing a
`v*` tag attaches it to a GitHub release.

### Module map

| Module | Responsibility |
|--------|----------------|
| `engine.py` | core scan / classify / boundary-search / extract |
| `stats.py` | chi-square randomness test (encrypted vs compressed) |
| `signatures.py` · `ransomnote.py` | ransomware fingerprinting from extension/footer and from ransom notes |
| `formats.py` | container/filesystem detection on the recoverable region (VHDX, ZIP/OOXML, NTFS/FAT, …) |
| `ntfs.py` | read files out of an NTFS volume inside a partially-encrypted / header-encrypted virtual disk |
| `sqlpages.py` | page-level SQL Server MDF/NDF recovery-quality check |
| `carve.py` | orchestrates PhotoRec over the recoverable region |
| `batch.py` | incident-wide directory triage + rollup |
| `report.py` | standalone HTML triage report (inline CSS + SVG entropy map) |
| `forensics.py` | before/after integrity proof + hash-chained audit log + case metadata |
| `source.py` | read-only input abstraction (files, images, raw Windows devices) |
| `gui.py` · `cli.py` | PySide6 desktop app · command-line entry point |

### Help ScanCrypt recognise a strain it doesn't name yet

Point it at one encrypted file:

```bash
scancrypt "somefile.newcrypt" --fingerprint
```

It prints a **privacy-safe** stub — extension, the family's trailing magic-candidate bytes,
the encryption pattern, and any nearby ransom note — as a ready-to-paste `signatures.yaml`
block **and** a pre-filled [GitHub issue](https://github.com/ironsightscyber/scancrypt/issues/new?template=ransomware-sample.yml)
link. It reads **no file contents**, so a victim can submit safely. (In the app: *Help improve
ScanCrypt…* after a scan.)

Contributions welcome — especially **new verified family signatures** (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

---

*ScanCrypt does not break, weaken, or bypass cryptography, and it does not recover
fully-encrypted data. Need an incident handled end to end — full extraction, database
rebuilds, forensic reporting? [IronSights](https://ironsights.com.au) does that as a paid
engagement; the tool stays free.*
