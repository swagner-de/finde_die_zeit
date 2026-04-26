# finde-die-zeit

![Version: 0.1.1](https://img.shields.io/badge/Version-0.1.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v2.1.0](https://img.shields.io/badge/AppVersion-v2.1.0-informational?style=flat-square)
Download and send DIE ZEIT ePaper editions automatically

## Features
- Automatically downloads DIE ZEIT ePaper (PDF/EPUB)
- Sends downloads via email (e.g. to Kindle)
- Tracks sent files to avoid duplicates
- Polls for new releases on a configurable interval

## Install

```bash
helm install finde-die-zeit oci://ghcr.io/swagner-de/finde_die_zeit/finde-die-zeit \
  --set env.FINDE_DIE_ZEIT_EMAIL="your@email.com" \
  --set env.FINDE_DIE_ZEIT_PASSWORD="your-password" \
  --set env.FINDE_DIE_ZEIT_FORMAT="epub" \
  --set env.FINDE_DIE_ZEIT_ANTI_CAPTCHA_API_KEY="your-key"
```

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://bjw-s-labs.github.io/helm-charts/ | common | 4.6.2 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| env | object | `{}` | Plain environment variables passed to the container |
| existingSecret | string | `""` | Existing secret containing environment variables as keys When set, the chart will not create its own secret |
| persistence | object | `{"config":{"accessMode":"ReadWriteOnce","enabled":true,"size":"100Mi"},"library":{"accessMode":"ReadWriteOnce","enabled":true,"size":"5Gi"}}` | Persistent storage configuration |
| persistence.config | object | `{"accessMode":"ReadWriteOnce","enabled":true,"size":"100Mi"}` | Config volume for session and history files |
| persistence.library | object | `{"accessMode":"ReadWriteOnce","enabled":true,"size":"5Gi"}` | Library volume for downloaded ePaper files |
| secretEnv | object | `{}` | Sensitive environment variables stored in a Kubernetes Secret Ignored when existingSecret is set |

## Security
- `runAsNonRoot: true`, UID/GID 65534 (nobody)
- `allowPrivilegeEscalation: false`
- All capabilities dropped
- Seccomp profile: `RuntimeDefault`

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| swagner-de | <swagner-de@users.noreply.github.com> |  |
