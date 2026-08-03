# Changelog

## 1.1.0

**Scan results change in this release.** Files that 1.0.x reported as fully intact or
front-only may now report more encrypted bytes and a lower recoverable percentage. The earlier
numbers were wrong in the optimistic direction — they claimed more was recoverable than was
true. **If you triaged anything with 1.0.x and acted on the number, re-scan it.**

Three detection defects were found by testing the scanner against known inputs before wider
release. All three erred the same way: reporting more recoverable than there was. For a
recovery tool that is the dangerous direction, because extracting on an inflated figure
returns a file with ciphertext stitched through it — a database that mounts and is quietly
wrong, which is worse than being told it is unrecoverable.

### Fixed

- **Intermittent (striped) encryption was under-reported.** Across eight realistic striping
  patterns the default scan under-reported seven. The worst case reported a file as
  `fully-intact`, 100% recoverable, when 6.25% of it was ciphertext. Three causes: leftover
  high-entropy points sitting at a regular stride were recorded but never acted on; a stripe
  narrower than the scan block averaged out against the plaintext around it and became
  invisible at any sampling density; and "nothing encrypted" from a sampling scan was taken at
  face value. The default scan now matches ground truth byte-for-byte on all eight patterns.

- **Front-only encryption was invisible to `--full`.** The mode offered as the more thorough
  one could not detect the most common ransomware pattern at all, reporting 100% recoverable
  on files the default scan measured exactly. A single high-entropy run has no spacing for the
  periodicity check to judge, so it fell through to "benign" — with nothing considering that
  the run started at offset 0, which is the entire signature. Both scan modes now agree.

- **Raw device paths crashed instead of explaining.** Running the documented raw-disk scan
  without elevating produced an uncaught `PermissionError` and a PyInstaller crash dump. It now
  names Administrator, says how to elevate, and notes that scanning a file or disk image needs
  no elevation. A mistyped device name gets the real naming scheme instead of a traceback.

- **`scancrypt --help` printed `usage: rprt`**, the pre-rename internal name.

### Corrected documentation

- **The chi-square false-positive rate was overstated as ~3e-5.** That figure came from a
  normal approximation to a right-skewed distribution, which understates its upper tail. The
  true rate is **~1.4e-4** — about one block in 7,000. Wilson-Hilferty gives 1.402e-4; measured
  over 40,000 CSPRNG blocks it is 1.0e-4 at 8 KiB and 1.5e-4 at 64 KiB. A lone flagged block
  inside a large encrypted run is expected noise, not a finding.

- **Single-block DEFLATE separability was overstated.** "Cleanly separable at >= 16 KiB" does
  not hold under zlib-ng, which CPython 3.14+ ships: its output sits closer to uniform than
  classic zlib's, and detection drops from 20/20 at 8 KiB to 4/20 at 64 KiB. The run-mean is
  the signal that holds across implementations.

The precision invariant is unchanged and intact: encrypted data is never mislabelled as
recoverable compressed content. Zero false positives across the full block-size sweep, and
across ZIP, xz, bzip2, gzip, SQLite, JPEG, PNG and back-to-back DEFLATE.

### Added

- **A verification corpus** (`samples/make_samples.py`). Builds four seeded, byte-identical
  sample images in about two minutes so anyone can check the recovery claims on their own
  machine without a real ransomware sample or a victim's data. Expected results are documented
  and measured, not estimated.

- **`pip install scancrypt` is now documented.** The package has been on PyPI since 1.0.0, but
  the README only showed an editable install from a clone, so no reader learned it existed.

- **Python 3.14 is now tested in CI** (advisory to start), alongside 3.12. The zlib-ng
  divergence above was Windows + 3.14 specific and had been invisible to a 3.12-only matrix.

### Changed

- Environment variables are now `SCANCRYPT_PHOTOREC`, `SCANCRYPT_FIRM_NAME` / `_URL` /
  `_BLURB` and `SCANCRYPT_READER_STATS`. The `RPRT_*` names still work as a silent fallback,
  so no existing setup breaks.

### Tests

194 to 230. New coverage for striping patterns across seeded seeds, front-only in both scan
modes, VHDX block-map reassembly with out-of-order and sparse blocks, and CLI failure paths.
The two precision tests are now seeded rather than using `os.urandom`: at the real false-
positive rate the old assert-exactly-zero test failed about one run in 130, and a flaky test in
the file backing the central accuracy claim is worse than useless.

## 1.0.1

First code-signed release. Windows binaries signed with a DigiCert OV certificate, key held in
an Azure Key Vault HSM.

## 1.0.0

Initial public release.
