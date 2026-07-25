# Contributing to ScanCrypt

Thanks for helping victims get their data back. ScanCrypt is free and
open-source (Apache-2.0), maintained by [IronSights](https://ironsights.com.au).
The most valuable contributions are **new ransomware-family signatures** and
**validation against real samples**, but bug fixes, docs, and format support
are all welcome.

## Contributor License Agreement (required)

Before we can merge your work, you need to agree to the
[Contributor License Agreement](CLA.md). You keep ownership of your
contribution; the CLA grants IronSights the rights to distribute it, including
the ability to license ScanCrypt under both open-source and, in future,
commercial terms. Agree by signing off your commits:

```bash
git commit -s     # adds "Signed-off-by: Your Name <you@example.com>"
```

The sign-off certifies you have read and agree to the CLA and the Developer
Certificate of Origin. Contributing on behalf of a company? Email
team@scancrypt.org for a Corporate CLA.

## The golden rule: honesty over coverage

ScanCrypt's credibility rests on never overstating what it knows. Please keep to
the same standard the codebase holds itself to:

- **Never fabricate a signature.** A wrong magic footer or a guessed encrypted
  fraction is worse than none, it produces false identifications. If you have
  not measured it, leave it `None`.
- **Mark provenance.** Every family carries `provenance`: `"validated"` (you
  confirmed it against a real sample) or `"public-reporting"` (from published
  threat intel, not yet verified). Only set `"validated"` for things you have
  actually observed.
- **Family-level indicators only.** Do not commit victim-specific data , 
  attacker contact addresses, victim IDs, keys, or any content from a specific
  victim's files or notes. Ransom-note markers must be the reusable template
  phrasing, not a victim's details.

## Adding or improving a family signature

Signatures are **plain data** in [`src/rprt/signatures.yaml`](src/rprt/signatures.yaml).
You do not need to touch any Python. Add a block under `families:` and open a PR.
The file has a full field reference and the rules at the top; the fields are:

- `name`: display name of the family (required).
- `extension_regex`: the encrypted-file extension, anchored (stable ones only;
  skip families that randomise the extension per victim).
- `footer_magic`: hex of a fixed trailer marker, only if you have measured it
  (allowed on `validated` rows only).
- `large_file_pattern`: `front-only`, `periodic-intermittent`, `configurable`,
  `full`, or `unknown`.
- `typical_max_encrypted_fraction`: 0..1, the intended encrypted extent, only if
  a specific default is documented (allowed on `validated` rows only).
- `provenance`: `validated` (you confirmed it against a real sample) or
  `public-reporting` (from published intel, not verified here).
- `note_name_regex` / `note_markers`: the ransom-note filename and distinctive
  template phrases (see [`src/rprt/ransomnote.py`](src/rprt/ransomnote.py)).
- `notes`: how it was confirmed, behaviour, caveats.

A CI check (`tests/test_signatures_yaml.py`) validates the schema and enforces
the honesty rules, so a PR that fabricates a footer or mislabels provenance fails
automatically. Run it locally first:

```bash
pip install -e ".[dev]"
pytest -q tests/test_signatures_yaml.py
```

Because signatures are data, not code, they carry over unchanged if the tool is
ever reimplemented in another language.

## Validating a family against a real sample

If you have a genuine encrypted sample (in a safe, isolated environment), you can
upgrade a `public-reporting` family to `validated`:

1. Measure the footer/extension/note and the large-file behaviour.
2. Update the YAML entry with what you measured, set `provenance: validated`, and
   record in `notes` how it was confirmed (without victim data).
3. If you can, add a redacted fixture or a scripted synthetic that reproduces the
   pattern so the test does not depend on the live sample.

## Code

- Match the surrounding style; keep the read-only, never-modify-the-input
  guarantee absolute.
- Prefer data (signature-table rows) over engine changes when adding family
  knowledge.
- New behaviour needs a test. The suite runs on Ubuntu and Windows in CI.

## Reporting bugs

Open an issue with the version/commit, the command, and a minimal reproduction.
For security issues, follow [SECURITY.md](SECURITY.md) instead.
