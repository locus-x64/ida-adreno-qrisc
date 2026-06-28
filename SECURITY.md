# Security

## Reporting

If you find a security-relevant issue in this project (memory safety, code
execution from a malicious firmware file, etc.), please open an issue marked
`security` or contact the repository owners directly.

This project is a **reverse-engineering toolkit**: it parses untrusted
firmware files and surfaces what's inside. It does not execute the firmware,
talk to a GPU, or modify the host system. Treat parser hardening as the
relevant scope.

## What this project is *for*

- Defensive security research on Adreno GPU firmware (e.g. analyzing
  CVE-2025-21479-class issues in shipped `*_sqe.fw` blobs).
- Open-source driver work on freedreno / Turnip.
- Educational and research reverse engineering.

The standard caveats for security tools apply: use it on firmware you have
the right to analyze.
