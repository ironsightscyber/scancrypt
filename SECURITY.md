# Security Policy

ScanCrypt is a **defensive** incident-response tool. It recovers the parts of
ransomware-encrypted files that were never encrypted; it does **not** decrypt,
break, weaken, or bypass cryptography, and it reads its inputs strictly
read-only.

## Scope and intended use

Use ScanCrypt only on systems and data you are authorized to examine, your own
environment, or an engagement you have been contracted to perform. It is
designed for victims, incident responders, and forensic examiners.

## Reporting a vulnerability

If you find a security issue in ScanCrypt itself (for example, a path-traversal
in the extraction code, a crash on malformed input that could be weaponised, or
a case where the tool writes to an input it should treat as read-only), please
report it privately rather than opening a public issue:

- Email **security@scancrypt.org**.
- Include the version/commit, a description, and a minimal reproduction if you
  can share one.

We aim to acknowledge reports within 3 business days and to agree a disclosure
timeline with you. Please give us reasonable time to fix an issue before any
public disclosure.

## What is *not* a vulnerability

- The tool reporting that a file is recoverable when the recovered data is
  incomplete or does not open, recovery is always "most, not all," and the
  reports say so. This is a stated limitation, not a security flaw.
- Inability to recover a fully-encrypted file, or a family the signature table
  does not yet name. Naming a strain never changes what is recovered.

## Handling of sensitive data

ScanCrypt processes potential evidence. It never transmits data anywhere; all
analysis is local. Reports and audit logs are written only to paths you choose.
If you contribute samples or logs to an issue, redact victim-identifying data
first, the project only needs family-level indicators (see CONTRIBUTING.md).
