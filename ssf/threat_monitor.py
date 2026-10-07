"""Real-time threat monitoring: event ingestion, detection rules and log analysis."""
import re
import threading
import time
from collections import defaultdict, deque

SIGNATURES = [
    ("SQL Injection", "high", re.compile(r"(?i)(\bunion\b.+\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|sleep\s*\()")),
    ("Cross-Site Scripting", "high", re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)")),
    ("Path Traversal", "high", re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd)")),
    ("Command Injection", "critical", re.compile(r"(;|\|\||&&|\|)\s*(cat|ls|wget|curl|nc|bash|sh)\b")),
    ("Scanner User-Agent", "low", re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster)")),
]
FAIL_TYPES = {"login_failed", "auth_failure"}
MAX_TRACKED_SOURCES = 10000


class ThreatMonitor:
    def __init__(self, cfg, store, alerter):
        self.cfg, self.store, self.alerter = cfg, store, alerter
        self._fails = defaultdict(deque)
        self._lock = threading.Lock()

    def ingest(self, event):
        """Store an event and return the list of detections it triggered."""
        src = str(event.get("source", "unknown"))[:100]
        etype = str(event.get("type", "generic"))[:50]
        payload = str(event.get("payload", ""))[:4000]
        detections = [{"threat": n, "severity": s} for n, s, rx in SIGNATURES if rx.search(payload)]
        if etype in FAIL_TYPES:
            now = time.time()
            with self._lock:
                if src not in self._fails and len(self._fails) >= MAX_TRACKED_SOURCES:
                    self._fails.pop(next(iter(self._fails)))
                q = self._fails[src]
                q.append(now)
                while q and now - q[0] > self.cfg.bruteforce_window:
                    q.popleft()
                hit = len(q) == self.cfg.bruteforce_threshold
            if hit:
                detections.append({"threat": "Brute Force", "severity": "high"})
        eid = self.store.add("events", {"source": src, "type": etype, "payload": payload[:500],
                                        "detections": detections})
        for d in detections:
            self.alerter.alert(d["severity"], f"{d['threat']} from {src}",
                               {"event_id": eid, "type": etype})
        return {"event_id": eid, "detections": detections}

    def analyze_log(self, text):
        """Run signatures over raw log text (e.g. web server logs)."""
        hits = []
        for n, line in enumerate(text.splitlines()[:50000], 1):
            for name, sev, rx in SIGNATURES:
                if rx.search(line[:4000]):
                    hits.append({"line": n, "threat": name, "severity": sev})
        return hits

    def status(self, window=3600):
        since = time.time() - window
        events = self.store.list("events", 1000, since)
        alerts = self.store.list("alerts", 1000, since)
        by_sev = defaultdict(int)
        for a in alerts:
            by_sev[a["severity"]] += 1
        return {"window_seconds": window, "events": len(events), "alerts": len(alerts),
                "alerts_by_severity": dict(by_sev), "recent_alerts": alerts[:10]}
