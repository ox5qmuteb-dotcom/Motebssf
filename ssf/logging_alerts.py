"""Logging setup and alert dispatch."""
import json
import logging
import urllib.request

log = logging.getLogger("ssf")


def setup_logging(cfg):
    handlers = [logging.StreamHandler()]
    if cfg.log_file:
        handlers.append(logging.FileHandler(cfg.log_file))
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers, force=True)


class Alerter:
    """Writes alerts to the log, the store and (optionally) an https webhook."""

    def __init__(self, cfg, store):
        self.cfg, self.store = cfg, store

    def alert(self, severity, title, details=None):
        details = details or {}
        level = logging.CRITICAL if severity == "critical" else logging.WARNING
        log.log(level, "ALERT [%s] %s", severity, title)
        self.store.add("alerts", {"severity": severity, "title": title, "details": details})
        url = self.cfg.alert_webhook
        if url.startswith("https://"):
            try:
                req = urllib.request.Request(
                    url, data=json.dumps({"severity": severity, "title": title}).encode(),
                    headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()  # nosec B310
            except Exception as exc:  # alerting must never break callers
                log.error("webhook failed: %s", exc)
