"""Security report generation (JSON / HTML / text)."""
import html
import time
from collections import Counter

ORDER = ["critical", "high", "medium", "low", "info"]


def build_report(store, scan_id=None):
    scan = store.get("scans", scan_id) if scan_id else (store.list("scans", 1) or [None])[0]
    findings = (scan or {}).get("findings", []) + (scan or {}).get("secrets", [])
    sev = Counter(f.get("severity", "info").lower() for f in findings)
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    score = max(0, 100 - sum(weights.get(k, 0) * v for k, v in sev.items()))
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_id": scan["id"] if scan else None,
        "target": (scan or {}).get("target"),
        "score": score,
        "summary": {k: sev.get(k, 0) for k in ORDER},
        "vulnerabilities": (scan or {}).get("findings", []),
        "secrets": (scan or {}).get("secrets", []),
        "tools": (scan or {}).get("tools", {}),
        "recent_alerts": store.list("alerts", 20),
    }


def render_html(r):
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(str(f.get('severity')))}</td><td>{e(str(f.get('rule') or f.get('type')))}</td>"
        f"<td>{e(str(f.get('file')))}:{e(str(f.get('line')))}</td><td>{e(str(f.get('message', f.get('match', ''))))}</td></tr>"
        for f in r["vulnerabilities"] + r["secrets"])
    summ = ", ".join(f"{e(k)}: {v}" for k, v in r["summary"].items())
    return (f"<!doctype html><meta charset=utf-8><title>SSF Report</title><h1>SSF Security Report</h1>"
            f"<p>Generated {e(r['generated_at'])} | Target: {e(str(r['target']))} | Score: {r['score']}/100</p>"
            f"<p>{summ}</p><table border=1 cellpadding=4><tr><th>Severity</th><th>Rule</th><th>Location</th>"
            f"<th>Details</th></tr>{rows}</table>")


def render_text(r):
    lines = [f"SSF Security Report  {r['generated_at']}", f"Target: {r['target']}  Score: {r['score']}/100",
             "Summary: " + ", ".join(f"{k}={v}" for k, v in r["summary"].items()), ""]
    for f in r["vulnerabilities"] + r["secrets"]:
        lines.append(f"[{f.get('severity')}] {f.get('rule') or f.get('type')} "
                     f"{f.get('file')}:{f.get('line')} {f.get('message', f.get('match', ''))}")
    return "\n".join(lines)
