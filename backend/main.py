import asyncio
import re
import ssl
import socket
import binascii
import httpx
import dns.resolver
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Literal
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

app = FastAPI(title="NetScope API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PROXY_MAP = {
    "direct": None,
    "de": "socks5://127.0.0.1:10808",
}

TOP_PORTS = sorted(set([
    # FTP
    20, 21, 990,
    # SSH / Telnet / Remote
    22, 23, 3389, 5900, 5901,
    # SMTP
    25, 465, 587,
    # DNS
    53,
    # HTTP / Web
    80, 443, 3000, 3001, 4000, 4200, 5000, 5173, 8008, 8080, 8443, 8888, 9000, 9090,
    # POP3 / IMAP
    110, 143, 993, 995,
    # NetBIOS / SMB
    137, 138, 139, 445,
    # LDAP
    389, 636,
    # SNMP
    161, 162,
    # BGP
    179,
    # RPC
    111, 135,
    # MSSQL
    1433,
    # Oracle
    1521,
    # MySQL
    3306,
    # PostgreSQL
    5432,
    # Redis
    6379,
    # RabbitMQ
    4369, 5672, 15672,
    # Memcached
    11211,
    # Zookeeper
    2181,
    # MongoDB
    27017,
    # Elasticsearch
    9200, 9300,
    # Kibana
    5601,
    # CouchDB
    5984,
    # Neo4j
    7474, 7687,
    # Cassandra
    9042,
    # Kafka
    9092,
    # Docker
    2375, 2376,
    # Kubernetes
    2379, 2380, 6443,
    # Proxy / VPN
    500, 1080, 1194, 1723, 3128, 4500, 8118, 8388,
    # Other
    79, 113, 119, 514, 515, 631, 873, 2049, 9418, 10000, 32400,
]))


class HostRequest(BaseModel):
    host: str
    proxy: Literal["direct", "de"] = "direct"


class PortScanRequest(BaseModel):
    host: str
    ports: list[int] = TOP_PORTS
    proxy: Literal["direct", "de"] = "direct"


class HttpRequest(BaseModel):
    url: str
    proxy: Literal["direct", "de"] = "direct"


class SslRequest(BaseModel):
    host: str
    port: int = 443
    proxy: Literal["direct", "de"] = "direct"


def sanitize_host(host: str) -> str:
    host = host.strip()
    if not re.match(r'^[a-zA-Z0-9.\-_]+$', host):
        raise HTTPException(status_code=400, detail="Invalid host")
    return host


STATIC_DIR = Path(__file__).parent / "frontend"

_scan_sem = asyncio.Semaphore(50)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/docs.html")
def docs():
    return FileResponse(STATIC_DIR / "docs.html")


@app.post("/api/dns")
async def dns_lookup(req: HostRequest):
    host = sanitize_host(req.host)
    results = {}
    resolver = dns.resolver.Resolver()
    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(host, rtype, lifetime=5)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []
    return {"host": host, "records": results}


@app.post("/api/ports")
async def port_scan(req: PortScanRequest):
    host = sanitize_host(req.host)
    if len(req.ports) > 200:
        raise HTTPException(status_code=400, detail="Max 200 ports")

    proxy_url = PROXY_MAP.get(req.proxy)

    async def check_port(port: int) -> dict:
        async with _scan_sem:
            try:
                if proxy_url:
                    from python_socks.async_.asyncio import Proxy
                    proxy = Proxy.from_url(proxy_url)
                    sock = await asyncio.wait_for(
                        proxy.connect(dest_host=host, dest_port=port),
                        timeout=5,
                    )
                    sock.close()
                else:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=3
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                return {"port": port, "open": True}
            except Exception:
                return {"port": port, "open": False}

    results = await asyncio.gather(*[check_port(p) for p in req.ports])
    return {"host": host, "results": results}


@app.post("/api/headers")
async def http_headers(req: HttpRequest):
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    proxy_url = PROXY_MAP.get(req.proxy)
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10,
            proxy=proxy_url,
        ) as client:
            resp = await client.head(url)
            return {
                "url": str(resp.url),
                "status": resp.status_code,
                "headers": dict(resp.headers),
            }
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/ssl")
async def ssl_cert(req: SslRequest):
    if not HAS_CRYPTO:
        raise HTTPException(status_code=501, detail="cryptography library not installed")

    host = sanitize_host(req.host)
    proxy_url = PROXY_MAP.get(req.proxy)

    def _fetch():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if proxy_url:
            from python_socks.sync import Proxy as SyncProxy
            raw_sock = SyncProxy.from_url(proxy_url).connect(
                dest_host=host, dest_port=req.port, timeout=10
            )
        else:
            raw_sock = socket.create_connection((host, req.port), timeout=10)

        with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)

        if not der:
            raise Exception("No certificate returned")

        cert = x509.load_der_x509_certificate(der, default_backend())

        def _attr(obj, oid):
            try:
                return obj.get_attributes_for_oid(oid)[0].value
            except Exception:
                return ""

        NameOID = x509.oid.NameOID
        subject_cn = _attr(cert.subject, NameOID.COMMON_NAME)
        subject_o  = _attr(cert.subject, NameOID.ORGANIZATION_NAME)
        issuer_cn  = _attr(cert.issuer,  NameOID.COMMON_NAME)
        issuer_o   = _attr(cert.issuer,  NameOID.ORGANIZATION_NAME)

        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for n in san_ext.value:
                if isinstance(n, x509.DNSName):
                    sans.append(f"DNS:{n.value}")
                elif isinstance(n, x509.IPAddress):
                    sans.append(f"IP:{n.value}")
        except Exception:
            pass

        fp_hex = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode().upper()
        fingerprint = ":".join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2))

        try:
            valid_from = cert.not_valid_before_utc.isoformat()
            valid_to   = cert.not_valid_after_utc.isoformat()
            now = datetime.now(timezone.utc)
            is_valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        except AttributeError:
            valid_from = cert.not_valid_before.isoformat() + "Z"
            valid_to   = cert.not_valid_after.isoformat() + "Z"
            now = datetime.utcnow()
            is_valid = cert.not_valid_before <= now <= cert.not_valid_after

        return {
            "host": host,
            "port": req.port,
            "subject": {"cn": subject_cn, "o": subject_o},
            "issuer":  {"cn": issuer_cn,  "o": issuer_o},
            "valid_from": valid_from,
            "valid_to": valid_to,
            "is_valid": is_valid,
            "sans": sans,
            "fingerprint_sha256": fingerprint,
            "serial": str(cert.serial_number),
        }

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _fetch)
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
