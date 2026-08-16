# Sextant

[![CI](https://github.com/agent-cyanez/sextant/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-cyanez/sextant/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/agent-cyanez/sextant)](https://github.com/agent-cyanez/sextant/releases)
[![Container](https://img.shields.io/badge/ghcr.io-sextant-blue)](https://ghcr.io/agent-cyanez/sextant)

TLS certificate expiry monitor with [ntfy](https://ntfy.sh) push notifications.

Part of the Docker monitoring suite: [Lookout](https://github.com/agent-cyanez/lookout) (container lifecycle) · [Beacon](https://github.com/agent-cyanez/beacon) (status page) · [Bosun](https://github.com/agent-cyanez/bosun) (log alerts) · **Sextant** (certificate expiry)

## Features

- Monitors TLS certificate expiry for any number of HTTPS endpoints
- Configurable warning and critical thresholds
- Push notifications via ntfy with priority levels (urgent/high/default)
- Alert cooldown prevents notification floods
- Zero dependencies — Python stdlib only
- Single file, Docker-native

## Quick Start

```bash
docker run -d \
  --name sextant \
  -e ENDPOINTS="example.com,mysite.org:8443" \
  -e NTFY_URL="http://ntfy:80" \
  -e NTFY_TOPIC="certs" \
  ghcr.io/agent-cyanez/sextant
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ENDPOINTS` | *(required)* | Comma-separated list of `host[:port]` to monitor. Default port is 443. |
| `CHECK_INTERVAL` | `3600` | Seconds between check cycles |
| `TIMEOUT` | `10` | Connection timeout in seconds |
| `WARN_DAYS` | `30` | Days before expiry to send warning |
| `CRIT_DAYS` | `7` | Days before expiry to send critical alert |
| `NTFY_URL` | `http://127.0.0.1:8888` | ntfy server URL |
| `NTFY_TOPIC` | `sextant` | ntfy topic for notifications |
| `ALERT_COOLDOWN` | `86400` | Seconds between repeat alerts for the same endpoint |

## Alert Priorities

| Condition | ntfy Priority |
|-----------|--------------|
| Certificate expired | `urgent` |
| Connection failed | `urgent` |
| Days left ≤ `CRIT_DAYS` | `high` |
| Days left ≤ `WARN_DAYS` | `default` |
| Healthy | No alert |

## Docker Compose

```yaml
services:
  sextant:
    image: ghcr.io/agent-cyanez/sextant
    container_name: sextant
    restart: unless-stopped
    environment:
      - ENDPOINTS=example.com,mysite.org,api.example.com:8443
      - CHECK_INTERVAL=3600
      - WARN_DAYS=30
      - CRIT_DAYS=7
      - NTFY_URL=http://ntfy:80
      - NTFY_TOPIC=certs
```

## Development

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
