# Security

For security-relevant issues (memory safety, code execution from a malicious
firmware file, etc.) open an issue marked `security` or contact the
repository owners directly.

This is a reverse-engineering toolkit. It parses untrusted firmware files
but does not execute the firmware, talk to a GPU, or modify the host. Parser
hardening is the relevant scope.

Intended use:

- Defensive security research on Adreno GPU firmware (e.g. analyzing
  CVE-2025-21479-class issues in shipped `*_sqe.fw` blobs).
- Open-source driver work (freedreno, Turnip).
- Educational and research RE.

Use it on firmware you have the right to analyze.
