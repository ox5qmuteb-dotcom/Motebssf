"""Vulnerability scanner: built-in Python checks plus bandit / safety / semgrep when installed."""
import json
import logging
import os
import re
import shutil
import subprocess

from .secrets_detector import iter_files

log = logging.getLogger("ssf.vuln")

RULES = [
    (r"\beval\s*\(", "SSF-PY001", "high", "Use of eval()"),
    (r"\bexec\s*\(", "SSF-PY002", "high", "Use of exec()"),
    (r"\bpickle\.loads?\s*\(", "SSF-PY003", "high", "Insecure deserialization (pickle)"),
    (r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?Safe)", "SSF-PY004", "high", "yaml.load without SafeLoader"),
    (r"shell\s*=\s*True", "SSF-PY005", "high", "subprocess with shell=True"),
    (r"\bhashlib\.(?:md5|sha1)\s*\(", "SSF-PY006", "medium", "Weak hash algorithm"),
    (r"verify\s*=\s*False", "SSF-PY007", "medium", "TLS certificate verification disabled"),
    (r"\.run\s*\([^)]*debug\s*=\s*True", "SSF-PY008", "medium", "Debug mode enabled"),
    (r"\.execute\s*\(\s*f?['\"].*(?:%s|\{|\"\s*\+|'\s*\+)", "SSF-PY009", "high", "Possible SQL injection (string-built query)"),
    (r"\binnerHTML\s*=", "SSF-JS001", "medium", "Possible DOM XSS (innerHTML)"),
    (r"\beval\s*\(|new Function\s*\(", "SSF-JS002", "high", "Dynamic code execution in JavaScript"),
]
_RULES = [(re.compile(p), i, s, m) for p, i, s, m in RULES]
EXTS = {".py": ("SSF-PY",), ".js": ("SSF-JS",), ".ts": ("SSF-JS",), ".html": ("SSF-JS",)}


def builtin_scan(root, exclude_dirs, max_bytes):
    out = []
    paths = [root] if os.path.isfile(root) else iter_files(root, set(exclude_dirs), max_bytes)
    for p in paths:
        prefixes = EXTS.get(os.path.splitext(p)[1])
        if not prefixes:
            continue
        try:
            with open(p, encoding="utf-8", errors="ignore") as fh:
                lines = fh.read(max_bytes).splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if "nosec" in line or "ssf:ignore" in line:
                continue
            for rx, rid, sev, msg in _RULES:
                if rid.startswith(prefixes) and rx.search(line):
                    out.append({"tool": "ssf", "rule": rid, "severity": sev, "message": msg,
                                "file": os.path.relpath(p, root) if p != root else p, "line": n})
    return out


def _run(cmd, timeout, cwd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, check=False)  # nosec B603


def _bandit(root, t):
    r = _run(["bandit", "-r", "-f", "json", "-q", "."], t, root)
    return [{"tool": "bandit", "rule": i["test_id"], "severity": i["issue_severity"].lower(),
             "message": i["issue_text"], "file": i["filename"], "line": i["line_number"]}
            for i in json.loads(r.stdout or "{}").get("results", [])]


def _safety(root, t):
    req = os.path.join(root, "requirements.txt")
    if not os.path.isfile(req):
        return []
    r = _run(["safety", "check", "-r", "requirements.txt", "--json"], t, root)
    data = json.loads(r.stdout or "{}")
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    return [{"tool": "safety", "rule": str(v.get("vulnerability_id", "")), "severity": "high",
             "message": f"{v.get('package_name')} {v.get('analyzed_version')}: {v.get('advisory', '')[:200]}",
             "file": "requirements.txt", "line": 0} for v in vulns]


def _semgrep(root, t):
    r = _run(["semgrep", "--config", "auto", "--json", "--quiet", "."], t, root)
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return [{"tool": "semgrep", "rule": i["check_id"],
             "severity": sev.get(i["extra"].get("severity"), "low"),
             "message": i["extra"].get("message", ""), "file": i["path"], "line": i["start"]["line"]}
            for i in json.loads(r.stdout or "{}").get("results", [])]


TOOLS = {"bandit": _bandit, "safety": _safety, "semgrep": _semgrep}


def scan(root, cfg):
    findings, tools = builtin_scan(root, cfg.exclude_dirs, cfg.max_file_bytes), {"ssf": "ok"}
    if cfg.external_tools and os.path.isdir(root):
        for name, fn in TOOLS.items():
            if not shutil.which(name):
                tools[name] = "not installed"
                continue
            try:
                findings += fn(root, cfg.tool_timeout)
                tools[name] = "ok"
            except Exception as exc:
                log.error("%s failed: %s", name, exc)
                tools[name] = "error"
    return findings, tools
