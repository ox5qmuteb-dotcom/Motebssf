"""Secret detection (API keys, tokens, credentials). Findings are always redacted."""
import math
import os
import re

PATTERNS = {
    "AWS Access Key ID": (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "critical"),
    "GitHub Token": (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "critical"),
    "Slack Token": (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "high"),
    "Google API Key": (r"\bAIza[0-9A-Za-z_-]{35}\b", "high"),
    "Stripe Secret Key": (r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b", "critical"),
    "Private Key": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", "critical"),
    "JWT": (r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "medium"),
    "Credentials in URL": (r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@[^\s/]+", "high"),
    "Generic Secret Assignment": (
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
        r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", "medium"),
}
_COMPILED = {k: (re.compile(p), s) for k, (p, s) in PATTERNS.items()}
_PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxxx|<.*>|\$\{.*\}|dummy|test")


def redact(value):
    return value[:4] + "*" * 8 if len(value) > 8 else "*" * 8


def entropy(s):
    if not s:
        return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in map(s.count, set(s)))


def scan_text(text, path="<text>"):
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:
            continue
        for name, (rx, sev) in _COMPILED.items():
            for m in rx.finditer(line):
                val = m.group(1) if m.groups() else m.group(0)
                if name == "Generic Secret Assignment" and (
                        _PLACEHOLDER.search(val) or entropy(val) < 2.5):
                    continue
                findings.append({"type": name, "severity": sev, "file": path,
                                 "line": lineno, "match": redact(val)})
    return findings


def iter_files(root, exclude_dirs, max_bytes):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                if os.path.islink(p) or os.path.getsize(p) > max_bytes:
                    continue
            except OSError:
                continue
            yield p


def scan_path(root, exclude_dirs=(), max_bytes=1_000_000):
    findings = []
    paths = [root] if os.path.isfile(root) else iter_files(root, set(exclude_dirs), max_bytes)
    for p in paths:
        try:
            with open(p, "rb") as fh:
                data = fh.read(max_bytes)
            if b"\0" in data[:1024]:
                continue
            findings += scan_text(data.decode("utf-8", "ignore"), os.path.relpath(p, root) if root != p else p)
        except OSError:
            continue
    return findings
