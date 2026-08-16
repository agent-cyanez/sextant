#!/usr/bin/env python3
"""Sextant — TLS certificate expiry monitor with ntfy alerts."""

import json
import logging
import os
import socket
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sextant")


def parse_endpoints(raw):
    """Parse ENDPOINTS env var into list of (host, port) tuples.

    Format: host[:port],host[:port],...
    Default port is 443.
    """
    endpoints = []
    if not raw or not raw.strip():
        return endpoints
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if entry.startswith("["):
            bracket_end = entry.find("]")
            if bracket_end == -1:
                continue
            host = entry[1:bracket_end]
            rest = entry[bracket_end + 1 :]
            port = int(rest.lstrip(":")) if rest.lstrip(":") else 443
        elif entry.count(":") == 1:
            host, port_str = entry.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                host = entry
                port = 443
            host = host
        else:
            host = entry
            port = 443
        endpoints.append((host, port))
    return endpoints


def check_certificate(host, port, timeout):
    """Connect to host:port and return certificate info dict.

    Returns dict with keys: host, port, subject, issuer, not_after, days_left, error
    """
    result = {
        "host": host,
        "port": port,
        "subject": None,
        "issuer": None,
        "not_after": None,
        "days_left": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()

        subject_parts = []
        for rdn in cert.get("subject", ()):
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    subject_parts.append(attr_value)
        result["subject"] = ", ".join(subject_parts) if subject_parts else host

        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_type, attr_value in rdn:
                if attr_type == "organizationName":
                    issuer_parts.append(attr_value)
        result["issuer"] = ", ".join(issuer_parts) if issuer_parts else "Unknown"

        not_after_str = cert.get("notAfter", "")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        result["not_after"] = not_after.isoformat()

        now = datetime.now(timezone.utc)
        delta = not_after - now
        result["days_left"] = delta.days

    except Exception as e:
        result["error"] = str(e)

    return result


def should_alert(result, warn_days, crit_days):
    """Determine alert priority based on certificate state.

    Returns (should_send, priority, message) tuple.
    """
    host = result["host"]
    port = result["port"]
    target = f"{host}:{port}" if port != 443 else host

    if result["error"]:
        return (True, "urgent", f"{target} — connection failed: {result['error']}")

    days = result["days_left"]
    if days is not None:
        if days <= 0:
            return (True, "urgent", f"{target} — certificate EXPIRED ({abs(days)} days ago)")
        if days <= crit_days:
            return (True, "high", f"{target} — certificate expires in {days} days (critical)")
        if days <= warn_days:
            return (True, "default", f"{target} — certificate expires in {days} days")

    return (False, None, None)


def send_ntfy(url, topic, title, message, priority="default"):
    """Send a notification via ntfy."""
    ntfy_url = f"{url.rstrip('/')}/{topic}"
    data = message.encode("utf-8")
    req = urllib.request.Request(ntfy_url, data=data, method="POST")
    req.add_header("Title", title)
    req.add_header("Priority", priority)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        log.error("ntfy send failed: %s", e)
        return False


def load_config():
    """Load configuration from environment variables."""
    return {
        "endpoints": parse_endpoints(os.environ.get("ENDPOINTS", "")),
        "interval": int(os.environ.get("CHECK_INTERVAL", "3600")),
        "timeout": int(os.environ.get("TIMEOUT", "10")),
        "warn_days": int(os.environ.get("WARN_DAYS", "30")),
        "crit_days": int(os.environ.get("CRIT_DAYS", "7")),
        "ntfy_url": os.environ.get("NTFY_URL", "http://127.0.0.1:8888"),
        "ntfy_topic": os.environ.get("NTFY_TOPIC", "sextant"),
        "cooldown": int(os.environ.get("ALERT_COOLDOWN", "86400")),
    }


def run_checks(config, alert_state):
    """Run certificate checks on all endpoints, send alerts as needed.

    Returns list of check results.
    """
    results = []
    now = time.time()

    for host, port in config["endpoints"]:
        result = check_certificate(host, port, config["timeout"])
        results.append(result)

        do_alert, priority, message = should_alert(
            result, config["warn_days"], config["crit_days"]
        )

        if do_alert:
            key = f"{host}:{port}"
            last_alert = alert_state.get(key, 0)
            if now - last_alert >= config["cooldown"]:
                sent = send_ntfy(
                    config["ntfy_url"],
                    config["ntfy_topic"],
                    "Sextant — Certificate Alert",
                    message,
                    priority,
                )
                if sent:
                    alert_state[key] = now
                    log.warning("Alert sent: %s", message)
                else:
                    log.error("Failed to send alert for %s", key)
            else:
                log.info("Alert suppressed (cooldown): %s", key)
        else:
            if result["days_left"] is not None:
                log.info(
                    "%s:%d — %d days remaining", host, port, result["days_left"]
                )

    return results


def main():
    config = load_config()

    if not config["endpoints"]:
        log.error("No endpoints configured. Set ENDPOINTS env var.")
        sys.exit(1)

    log.info(
        "Sextant starting — monitoring %d endpoints, interval %ds",
        len(config["endpoints"]),
        config["interval"],
    )
    for host, port in config["endpoints"]:
        log.info("  %s:%d", host, port)

    alert_state = {}

    while True:
        try:
            run_checks(config, alert_state)
        except Exception as e:
            log.error("Check cycle failed: %s", e)

        time.sleep(config["interval"])


if __name__ == "__main__":
    main()
