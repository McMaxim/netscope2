# NetScope

Web-based network diagnostics toolkit. Run Ping, DNS lookup, Port scan, HTTP headers inspection, and Traceroute — right from your browser.

**Live demo:** https://yourdomain.com  
**Docs:** https://yourdomain.com/docs.html

## Features

| Tool | Description |
|---|---|
| 📡 Ping | ICMP echo with RTT stats (4 packets) |
| 🔍 DNS Lookup | A, AAAA, MX, NS, TXT records |
| 🔌 Port Scanner | TCP connect scan, up to 20 ports |
| 📋 HTTP Headers | Response headers with redirect follow |
| 🗺️ Traceroute | Network path, up to 15 hops |

## Stack

- **Backend:** Python / FastAPI / uvicorn
- **Frontend:** Vanilla HTML + CSS + JS (no frameworks)
- **Proxy:** Caddy (auto HTTPS via Let's Encrypt)
- **Runtime:** Docker + Docker Compose

## Self-hosting

Requirements: Docker, Docker Compose, a domain pointing to your server.

```bash
git clone https://github.com/McMaxim/netscope.git
cd netscope

# Set your domain
sed -i 's/yourdomain.com/your.actual.domain/g' Caddyfile

docker compose up -d
```

Caddy automatically obtains and renews TLS certificates. No manual cert setup needed.

## Architecture

```
Browser
  └─▶ Caddy (:443, auto-TLS)
        ├─▶ /api/* ──▶ FastAPI backend (:8000)
        └─▶ /*     ──▶ Static frontend files
```

## API

All endpoints: `POST /api/<tool>`, JSON body, JSON response.

```
POST /api/ping        {"host": "google.com"}
POST /api/dns         {"host": "github.com"}
POST /api/ports       {"host": "1.1.1.1", "ports": [80, 443]}
POST /api/headers     {"url": "https://example.com"}
POST /api/traceroute  {"host": "8.8.8.8"}
GET  /api/health
```

See [/docs.html](https://yourdomain.com/docs.html) for full API reference.

## License

MIT
