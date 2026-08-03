# Verification corpus

A reproducible set of sample images for checking ScanCrypt's claims on your own machine,
without needing a real ransomware sample or a victim's data.

Every number below was **measured**, not estimated. If you build the corpus and get a
different answer, that is a bug and we want to hear about it.

## Build it

```bash
pip install scancrypt
python samples/make_samples.py
```

Two minutes, 256 MiB. Everything is seeded, so your files are byte-identical to ours —
`samples/corpus/manifest.json` records the SHA-256 of each. Re-check any time with
`python samples/make_samples.py --verify`.

## What's in it — and what isn't

The samples contain **no real data and no real ransomware output.**

- The "encrypted" regions are uniform random bytes from a seeded generator. That is what a
  block cipher in a streaming mode looks like statistically, which is all the entropy and
  chi-square analysis ever sees. Nothing here is produced by, or derived from, a malware
  binary, and we do not distribute one.
- The "intact" regions are synthetic record-structured text, standing in for the low-entropy
  content that fills a real database or document store.

This is a deliberate limit. We can't ship a customer's encrypted database, and we won't ship
a working encryptor so you can make your own. If you'd rather not trust bytes we generated,
the honest alternative is to build your own sample: take any large file of your own, overwrite
the first megabyte with `os.urandom(1024*1024)`, and point ScanCrypt at it. The tool has no
idea where the bytes came from.

Separately, the Makop/Phobos `.ndm448` signature in `src/rprt/signatures.yaml` **is** validated
against real samples and the encryptor disassembly — it is tagged `provenance: validated`. The
other seven families are `provenance: public-reporting` (extension patterns only, no fabricated
footers) and labelled as such in the source.

## Expected results

Measured on Python 3.14.4, numpy 2.5.1, scancrypt 1.1.0.

| Sample | Injected | Reported pattern | Reported encrypted | Recoverable |
|---|---|---|---|---|
| `01-front-only-large.img` | 1 MiB front of 128 MiB | `front-only` | **1,048,576 B (0.7812%)** | 99.2188% |
| `02-front-only-narrow-boundary.img` | 200,704 B front of 32 MiB | `front-only` | **200,704 B (0.5981%)** | 99.4019% |
| `03-periodic-intermittent.img` | 8 × 512 KiB stripes in 64 MiB | `periodic-intermittent` | **4,194,304 B (6.25%)** | 93.75% |
| `04-compressed-benign.img` | nothing — real DEFLATE | `compressed-benign` | **0 B (0%)** | 100% |

```bash
scancrypt samples/corpus/01-front-only-large.img
scancrypt samples/corpus/02-front-only-narrow-boundary.img
scancrypt samples/corpus/03-periodic-intermittent.img
scancrypt samples/corpus/04-compressed-benign.img
```

Every one of these is the plain default invocation — no flags, no `--full`, no tuning.

Samples 1 and 2 return the encrypted length **exactly** — to the byte, not approximately.
Sample 2 uses 200,704 bytes because that is the boundary width measured in the incident that
prompted this tool: a coarse fixed-interval scan can miss a region that narrow entirely and
write the file off as lost.

Sample 4 is the case entropy alone gets wrong. It is real DEFLATE output — the algorithm
behind ZIP, OOXML, PNG and gzip — and reads ~8 bits per byte, same as ciphertext. An
entropy-only tool calls it encrypted and writes off an intact archive. ScanCrypt reports it as
fully intact.

## How sample 3 is found

Sample 3 is the interesting one, because building this corpus is what exposed a real bug.

The default scan is a boundary search — it samples the file rather than reading all of it, so
a 100 GB disk doesn't have to be read end to end. Striped encryption defeats a naive version
of that: the first stripe looks like a front boundary, and the rest fall between samples. The
scanner used to report this file as `front-only`, 524,288 bytes, **99.2% recoverable against a
true 93.75%** — optimistic, which is the worst direction for a recovery estimate.

It now recognises the pattern from the evidence it was already collecting. The leftover
high-entropy points sit at a dead-regular stride:

```
8388608, 16777216, 25165824, 33554432, 41943040, 50331648, 58720256
```

Every 8 MiB exactly. Scattered dense content — a database's LOB pages, media, a compressed
region — lands at irregular gaps. Encryption applied at a fixed stride does not. That
regularity now escalates the scan automatically, so the default invocation reports
`periodic-intermittent` and 93.75% without being asked.

Two related limits were fixed at the same time. A stripe narrower than the scan block used to
be invisible at any sampling density — 4 KiB stripes inside an 8 KiB block average out against
the plaintext around them and read as clean — so a scan that concludes nothing is encrypted
now re-checks at a finer block. And on files small enough that reading them is cheap, a
`fully-intact` verdict is confirmed with a full scan rather than trusted from samples.

The same exercise found a third bug in the mode that is supposed to be the thorough one:
`--full` could not detect **front-only** encryption at all, because a single high-entropy run
has no spacing for the periodicity check to judge and fell through to "benign". It reported
100% recoverable on samples 1 and 2, which the boundary scan measured exactly. Both modes now
agree on every sample here.

The limit that remains is resolution: ScanCrypt cannot see an encrypted stripe much narrower
than `--block-size`, which is why a scan that finds nothing now re-checks at a finer block
rather than taking the first answer. Sample 3's stripes are 512 KiB, comfortably wider than
the 8 KiB default, so it is detected at every block size — the fine-grained case is covered by
the 4 KiB and 2 KiB patterns in `tests/test_intermittent.py` instead.

## Extraction

```bash
scancrypt samples/corpus/01-front-only-large.img --extract recovered.bin
```

Writes the intact byte range. The input is opened read-only and is never modified — verify
with the SHA-256 in `manifest.json` after any operation.

For an evidence-grade run with a tamper-evident audit trail:

```bash
scancrypt samples/corpus/01-front-only-large.img \
    --extract recovered.bin --audit-log audit.jsonl \
    --case-id CASE-0001 --examiner "A. Analyst" --evidence-id SAMPLE-01
```

## What this corpus does not prove

It shows the measurement is correct on known inputs. It does not show that a given ransomware
family leaves this much behind — that depends on the crew, the file size and how long they
had. Recoverability is always reported as measured, per file, and always as *most, not all*.

Fully-encrypted files and small files are out of scope: if a crew had time to encrypt the
whole thing, there is nothing here to recover, and ScanCrypt will tell you so rather than
pretend otherwise.

One limit is fundamental rather than a matter of resolution: **incompressible data cannot be
told apart from ciphertext.** A PNG of pure random noise, or a file that is already encrypted,
is statistically uniform — and uniform is exactly what encryption looks like. No entropy or
chi-square test can separate them, so such a file will be reported as encrypted. Ordinary
content is unaffected: screenshots, photographs, JPEGs, ZIP, gzip, bzip2, xz, SQLite databases
and back-to-back DEFLATE streams were all measured reporting 0 encrypted bytes.
