# SNI Proxy

[![Docker Build](https://github.com/TreexHD/SNIProxy/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/TreexHD/SNIProxy/actions/workflows/docker-publish.yml)

Pure Python asyncio **TLS SNI proxy** with port-knocking whitelist and auto-blacklist.  
**Zero external dependencies** — stdlib only.

> Inspects TLS ClientHello → extracts SNI hostname → matches against configurable domain rules → relays traffic directly or through an upstream HTTP proxy. **No TLS decryption.**

## ✨ Features

| Feature | Description |
|---------|-------------|
| **SNI Extraction** | Parses TLS 1.0–1.3 ClientHello, zero decryption |
| **Domain Filtering** | Exact, wildcard (`*.example.com`), regex (`/pattern/` or `~pattern`) |
| **Port-Knock Whitelist** | Clients must knock a port to gain access (SQLite-backed) |
| **Auto-Blacklist** | IPs sending unmatched SNI get auto-banned after threshold |
| **Upstream HTTP Proxy** | Optional HTTP CONNECT tunneling with Basic auth |
| **IPv4 / IPv6** | Dual-stack support with configurable preference |
| **Persistent Storage** | SQLite database survives restarts |
| **Zero Dependencies** | Python stdlib only — no `pip install` needed |
| **Docker** | Multi-arch image (AMD64 + ARMv7) |

---

## 🚀 Quick Start

### Local

```bash
cp config.example.json config.json   # Edit your config
python sniproxy.py
```

### Docker

```bash
docker run -d \
  --name sniproxy \
  -v $(pwd)/config.json:/app/config.json:ro \
  -v $(pwd)/sniproxy.db:/app/sniproxy.db \
  -p 443:443 \
  -p 9999:9999 \
  treexhd/sniproxy:latest
```

> Mount your `config.json` directly into the container. The SQLite database (`sniproxy.db`) should also be mounted for persistence.

### Docker Compose

```yaml
services:
  sniproxy:
    image: treexhd/sniproxy:latest
    container_name: sniproxy
    restart: unless-stopped
    volumes:
      - ./config.json:/app/config.json:ro
      - ./sniproxy.db:/app/sniproxy.db
    ports:
      - "443:443/tcp"
      - "9999:9999/tcp"
```

---

## ⚙️ Configuration

All settings are in `config.json`. Copy `config.example.json` as a template.

### Listen

```json
{
  "listen": {
    "host": "0.0.0.0",
    "port": 443
  }
}
```

> Use `"::"` for IPv4+IPv6 dual-stack.

### Domain Rules

Only matching domains will be proxied. Three formats supported:

```json
{
  "domains": [
    "example.com",
    "*.google.com",
    "/^cdn\\d+\\.example\\.com$/",
    "~^(.+\\.)?fast\\.com$"
  ]
}
```

| Format | Example | Matches |
|--------|---------|---------|
| Exact | `example.com` | `example.com` only |
| Wildcard | `*.google.com` | `www.google.com`, `mail.google.com` |
| Regex (Slash) | `/^cdn\d+\.cdn\.com$/` | `cdn1.cdn.com`, `cdn99.cdn.com` |
| Regex (Nginx style) | `~^(.+\\.)?fast\\.com$` | `fast.com`, `www.fast.com` |

### Port-Knock Whitelist

When enabled, clients must connect to `knock_port` first to whitelist their IP:

```json
{
  "port_knock": {
    "enabled": true,
    "knock_port": 9999,
    "whitelist_ttl": 3600,
    "cleanup_interval": 60
  }
}
```

**Usage:**
```bash
# Step 1: Knock
nc -z your-server 9999

# Step 2: Use proxy (within TTL)
curl --resolve example.com:443:your-server https://example.com/
```

### Auto-Blacklist

Automatically ban IPs that keep sending unmatched SNI requests:

```json
{
  "auto_blacklist": {
    "enabled": true,
    "strikes": 10,
    "window_seconds": 60,
    "ban_days": 7
  }
}
```

### Upstream HTTP Proxy

Tunnel all traffic through an HTTP CONNECT proxy:

```json
{
  "upstream_proxy": {
    "host": "proxy.example.com",
    "port": 8080,
    "username": "",
    "password": ""
  }
}
```

### Network & Database

```json
{
  "network": {
    "prefer_ipv6": false,
    "connect_timeout": 10,
    "relay_buffer_size": 8192
  },
  "database": {
    "path": "sniproxy.db"
  },
  "logging": {
    "level": "INFO"
  }
}
```

---

## 🔒 How It Works

```
Client ──TLS ClientHello──▶ SNI Proxy
                              │
                    ┌─────────┼─────────┐
                    ▼         ▼         ▼
              Blacklisted?  Whitelisted?  Parse SNI
                  │         (if knock     │
                  │          enabled)     ▼
                  ▼              │    Domain match?
                 DROP           ▼        │
                               DROP   ┌──┴──┐
                                     YES    NO
                                      │     │
                                      ▼     ▼
                                   RELAY   DROP
                                   (direct  + strike
                                   or via    counter
                                   proxy)
```

- **No TLS decryption** — the proxy only reads the ClientHello to extract the SNI hostname
- Traffic is relayed as raw TCP bytes between client and target
- Database persists whitelist/blacklist across restarts

---

## 🐳 Docker Build

### Build locally

```bash
docker build -t sniproxy .
```

### Multi-arch build

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t treexhd/sniproxy:latest --push .
```

### GitHub Actions

The included workflow (`.github/workflows/docker-publish.yml`) automatically builds and pushes multi-arch images on:
- Push to `main` branch
- Version tags (`v*`)

**Required GitHub Secrets:**

| Secret | Description |
|--------|-------------|
| `DOCKERHUB_USERNAME` | Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token |

---

## 📁 Project Structure

```
SNIProxy/
├── sniproxy.py                    # Main proxy server (single file)
├── config.example.json            # Configuration template
├── config.json                    # Your config (gitignored)
├── Dockerfile                     # Container image
├── .gitignore
├── .github/
│   └── workflows/
│       └── docker-publish.yml     # CI/CD pipeline
└── README.md
```

## Requirements

- Python 3.10+
- No external packages

## License

MIT
