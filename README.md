# finde_die_zeit

Automatically download [DIE ZEIT](https://www.zeit.de/) ePaper editions (PDF/EPUB) and optionally send them to your email or Kindle.

Requires a DIE ZEIT Premium/Digital subscription and an [anti-captcha.com](https://anti-captcha.com/) API key for automated login.

## Features

- Downloads the current DIE ZEIT ePaper in PDF and/or EPUB format
- Sends downloads via email (e.g. to Kindle)
- Tracks sent files to avoid duplicates
- Polls for new releases on a configurable interval
- Runs as a Docker container or Kubernetes deployment

## Quick Start

### Using Docker

```bash
docker run --rm \
  -e FINDE_DIE_ZEIT_EMAIL="your@email.com" \
  -e FINDE_DIE_ZEIT_PASSWORD="your-password" \
  -e FINDE_DIE_ZEIT_FORMAT="epub" \
  -e FINDE_DIE_ZEIT_ANTI_CAPTCHA_API_KEY="your-key" \
  -e FINDE_DIE_ZEIT_LIBRARY_PATH="/data" \
  -v ./downloads:/data \
  ghcr.io/swagner-de/finde_die_zeit:latest \
  now --previous-release 0
```

### Using pip

```bash
pip install git+https://github.com/swagner-de/finde_die_zeit.git
finde-die-zeit --email you@example.com --password secret \
  --format epub --anti-captcha-api-key your-key \
  now --previous-release 0
```

## Commands

### `now`

Download the current or a specific release.

```bash
python finde_die_zeit.py [global options] now [options]
```

| Option | Description |
|---|---|
| `--previous-release N` | Download the Nth previous release (0 = current) |
| `--release-date DATE` | Download by date (`YYYY-MM-DD` or `DD.MM.YYYY`) |
| `--session-file PATH` | Persist login session to file |

### `wait-for-next-release`

Poll for new releases and download them.

```bash
python finde_die_zeit.py [global options] wait-for-next-release [options]
```

| Option | Description |
|---|---|
| `--interval N` | Check every N hours (default: 4) |

### `wait-for-next-release-and-send`

Poll for new releases, download, and email them.

```bash
python finde_die_zeit.py [global options] wait-for-next-release-and-send [options]
```

| Option | Description |
|---|---|
| `--interval N` | Check every N hours (default: 4) |
| `--recipients EMAIL` | Recipient email(s), repeatable |
| `--send-from EMAIL` | Sender email address |
| `--smtp-server HOST` | SMTP server hostname |
| `--smtp-port PORT` | SMTP port (default: 587) |
| `--smtp-user USER` | SMTP username (default: `--send-from`) |
| `--smtp-password PASS` | SMTP password |
| `--start-tls` | Use STARTTLS |
| `--force-send` | Send even if already sent |
| `--history-file PATH` | Track sent files (default: `history.yaml`) |

### Global Options

| Option | Description |
|---|---|
| `--email EMAIL` | DIE ZEIT account email |
| `--password PASS` | DIE ZEIT account password |
| `--format FORMAT` | `pdf` and/or `epub` (repeatable) |
| `--log-level LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `--library-path PATH` | Download directory (default: `Die_Zeit`) |
| `--anti-captcha-api-key KEY` | [anti-captcha.com](https://anti-captcha.com/) API key |

All options can be set via environment variables with the `FINDE_DIE_ZEIT_` prefix (e.g. `FINDE_DIE_ZEIT_EMAIL`).

## Docker Compose

```yaml
services:
  finde_die_zeit:
    image: ghcr.io/swagner-de/finde_die_zeit:latest
    environment:
      FINDE_DIE_ZEIT_EMAIL: "your@email.com"
      FINDE_DIE_ZEIT_PASSWORD: "your-password"
      FINDE_DIE_ZEIT_FORMAT: "epub"
      FINDE_DIE_ZEIT_ANTI_CAPTCHA_API_KEY: "your-key"
      FINDE_DIE_ZEIT_LIBRARY_PATH: "/data/library"
      FINDE_DIE_ZEIT_SESSION_FILE: "/data/config/session.yaml"
      FINDE_DIE_ZEIT_RECIPIENTS: "user@kindle.com"
      FINDE_DIE_ZEIT_SEND_FROM: "sender@example.com"
      FINDE_DIE_ZEIT_SMTP_SERVER: "smtp.example.com"
      FINDE_DIE_ZEIT_SMTP_PORT: "587"
      FINDE_DIE_ZEIT_SMTP_PASSWORD: "your-smtp-password"
      FINDE_DIE_ZEIT_SMTP_STARTTLS: "1"
    volumes:
      - ./data:/data
    command: ["wait-for-next-release-and-send"]
```

## Helm Chart

```bash
helm install finde-die-zeit oci://ghcr.io/swagner-de/finde_die_zeit/finde-die-zeit \
  --set env.FINDE_DIE_ZEIT_FORMAT="epub" \
  --set env.FINDE_DIE_ZEIT_LIBRARY_PATH="/data/library" \
  --set env.FINDE_DIE_ZEIT_RECIPIENTS="user@kindle.com" \
  --set env.FINDE_DIE_ZEIT_SEND_FROM="sender@example.com" \
  --set env.FINDE_DIE_ZEIT_SMTP_SERVER="smtp.example.com" \
  --set env.FINDE_DIE_ZEIT_SMTP_STARTTLS="1" \
  --set secretEnv.FINDE_DIE_ZEIT_EMAIL="your@email.com" \
  --set secretEnv.FINDE_DIE_ZEIT_PASSWORD="your-password" \
  --set secretEnv.FINDE_DIE_ZEIT_ANTI_CAPTCHA_API_KEY="your-key" \
  --set secretEnv.FINDE_DIE_ZEIT_SMTP_PASSWORD="your-smtp-password"
```

Sensitive values are stored in a Kubernetes Secret. To use an existing secret instead:

```bash
helm install finde-die-zeit oci://ghcr.io/swagner-de/finde_die_zeit/finde-die-zeit \
  --set existingSecret="my-secret" \
  --set env.FINDE_DIE_ZEIT_FORMAT="epub" \
  ...
```

See [`chart/values.yaml`](chart/values.yaml) for all configuration options.

## License

[MIT](LICENSE)
