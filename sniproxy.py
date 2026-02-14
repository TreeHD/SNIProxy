#!/usr/bin/env python3
"""
SNI Proxy — TLS SNI-based transparent proxy with port-knocking whitelist.

Features:
  - TLS ClientHello SNI extraction (no decryption)
  - Domain matching: exact / wildcard / regex
  - Port-knocking IP whitelist (SQLite-backed)
  - Auto-blacklist for IPs sending unmatched SNI
  - Optional upstream HTTP CONNECT proxy
  - IPv4 / IPv6 support
  - Zero external dependencies (stdlib only)
  - Pure asyncio, single file
"""

import asyncio
import base64
import ipaddress
import logging
import os
import re
import socket
import sqlite3
import struct
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import json

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("sniproxy")


# ---------------------------------------------------------------------------
# TLS ClientHello Parser
# ---------------------------------------------------------------------------
def parse_client_hello(data: bytes) -> str | None:
    """Extract SNI hostname from the first TLS record (ClientHello).

    Returns the hostname string or None if parsing fails.
    """
    try:
        # TLS record: ContentType(1) | Version(2) | Length(2)
        if len(data) < 5:
            return None
        content_type = data[0]
        if content_type != 0x16:  # Handshake
            return None

        # record_version = struct.unpack("!H", data[1:3])[0]
        record_length = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + record_length:
            return None

        handshake = data[5 : 5 + record_length]

        # Handshake: HandshakeType(1) | Length(3)
        if len(handshake) < 4:
            return None
        hs_type = handshake[0]
        if hs_type != 0x01:  # ClientHello
            return None

        hs_length = struct.unpack("!I", b"\x00" + handshake[1:4])[0]
        if len(handshake) < 4 + hs_length:
            return None

        hello = handshake[4 : 4 + hs_length]
        pos = 0

        # ClientHello: Version(2) + Random(32)
        pos += 2 + 32  # skip version + random

        # Session ID
        if pos >= len(hello):
            return None
        session_id_len = hello[pos]
        pos += 1 + session_id_len

        # Cipher Suites
        if pos + 2 > len(hello):
            return None
        cipher_suites_len = struct.unpack("!H", hello[pos : pos + 2])[0]
        pos += 2 + cipher_suites_len

        # Compression Methods
        if pos >= len(hello):
            return None
        comp_methods_len = hello[pos]
        pos += 1 + comp_methods_len

        # Extensions
        if pos + 2 > len(hello):
            return None
        extensions_len = struct.unpack("!H", hello[pos : pos + 2])[0]
        pos += 2

        extensions_end = pos + extensions_len
        while pos + 4 <= extensions_end:
            ext_type = struct.unpack("!H", hello[pos : pos + 2])[0]
            ext_len = struct.unpack("!H", hello[pos + 2 : pos + 4])[0]
            pos += 4

            if ext_type == 0x0000:  # server_name extension
                # ServerNameList length(2)
                if pos + 2 > extensions_end:
                    break
                # sn_list_len = struct.unpack("!H", hello[pos : pos + 2])[0]
                sn_pos = pos + 2

                # ServerName: NameType(1) | Length(2) | Name
                if sn_pos + 3 > extensions_end:
                    break
                name_type = hello[sn_pos]
                name_len = struct.unpack("!H", hello[sn_pos + 1 : sn_pos + 3])[0]
                sn_pos += 3

                if name_type == 0x00:  # host_name
                    if sn_pos + name_len > len(hello):
                        break
                    return hello[sn_pos : sn_pos + name_len].decode("ascii", errors="replace")

            pos += ext_len

    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Domain Matcher
# ---------------------------------------------------------------------------
class DomainMatcher:
    """Match hostnames against a list of exact / wildcard / regex rules."""

    def __init__(self, domain_rules: list[str]):
        self._patterns: list[re.Pattern] = []
        for rule in domain_rules:
            pattern = self._compile_rule(rule)
            if pattern:
                self._patterns.append(pattern)
                logger.debug("Domain rule: %s -> %s", rule, pattern.pattern)

    @staticmethod
    def _compile_rule(rule: str) -> re.Pattern | None:
        rule = rule.strip()
        if not rule:
            return None

        # Regex rule: ~pattern
        if rule.startswith("~"):
            try:
                return re.compile(rule[1:], re.IGNORECASE)
            except re.error as exc:
                logger.warning("Invalid regex rule '%s': %s", rule, exc)
                return None

        # Regex rule: /pattern/
        if rule.startswith("/") and rule.endswith("/") and len(rule) > 2:
            try:
                return re.compile(rule[1:-1], re.IGNORECASE)
            except re.error as exc:
                logger.warning("Invalid regex rule '%s': %s", rule, exc)
                return None

        # Wildcard rule: *.example.com -> regex
        if "*" in rule or "?" in rule:
            # Escape everything except * and ?
            escaped = re.escape(rule)
            escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")
            return re.compile(f"^{escaped}$", re.IGNORECASE)

        # Exact match
        return re.compile(f"^{re.escape(rule)}$", re.IGNORECASE)

    def match(self, hostname: str) -> bool:
        """Return True if hostname matches any configured rule."""
        for pattern in self._patterns:
            if pattern.search(hostname):
                return True
        return False


# ---------------------------------------------------------------------------
# IP Database (SQLite) — whitelist + blacklist
# ---------------------------------------------------------------------------
class IPDatabase:
    """SQLite-backed IP whitelist and blacklist."""

    def __init__(self, db_path: str = "sniproxy.db"):
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self):
        # Check if path is a directory (Docker mount artifact)
        path = Path(self.db_path)
        if path.is_dir():
            raise IsADirectoryError(
                f"Database path '{self.db_path}' is a directory. "
                "If using Docker, ensure you are mounting a file or a folder correctly."
            )
        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                ip         TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT            -- NULL = permanent
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                ip         TEXT PRIMARY KEY,
                reason     TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT            -- NULL = permanent
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS strikes (
                ip         TEXT NOT NULL,
                sni        TEXT,
                created_at TEXT NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_strikes_ip_time
            ON strikes (ip, created_at)
        """)
        self._conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def normalise_ip(ip: str) -> str:
        """Normalise IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4)."""
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(addr)
        except ValueError:
            return ip

    # -- whitelist -----------------------------------------------------------
    def whitelist_add(self, ip: str, ttl_seconds: int = 0):
        ip = self.normalise_ip(ip)
        now = self._now()
        expires = None
        if ttl_seconds > 0:
            expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO whitelist (ip, created_at, expires_at) VALUES (?, ?, ?)",
            (ip, now, expires),
        )
        self._conn.commit()

    def whitelist_check(self, ip: str) -> bool:
        ip = self.normalise_ip(ip)
        row = self._conn.execute(
            "SELECT expires_at FROM whitelist WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return False
        expires_at = row[0]
        if expires_at is not None:
            if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
                self._conn.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
                self._conn.commit()
                return False
        return True

    def whitelist_cleanup(self) -> int:
        now = self._now()
        cur = self._conn.execute(
            "DELETE FROM whitelist WHERE expires_at IS NOT NULL AND expires_at < ?", (now,)
        )
        self._conn.commit()
        return cur.rowcount

    def whitelist_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]

    # -- blacklist -----------------------------------------------------------
    def blacklist_add(self, ip: str, reason: str = "", ban_days: int = 0):
        ip = self.normalise_ip(ip)
        now = self._now()
        expires = None
        if ban_days > 0:
            expires = (datetime.now(timezone.utc) + timedelta(days=ban_days)).isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO blacklist (ip, reason, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (ip, reason, now, expires),
        )
        self._conn.commit()

    def blacklist_check(self, ip: str) -> bool:
        ip = self.normalise_ip(ip)
        row = self._conn.execute(
            "SELECT expires_at FROM blacklist WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return False
        expires_at = row[0]
        if expires_at is not None:
            if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
                self._conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
                self._conn.commit()
                return False
        return True

    def blacklist_cleanup(self) -> int:
        now = self._now()
        cur = self._conn.execute(
            "DELETE FROM blacklist WHERE expires_at IS NOT NULL AND expires_at < ?", (now,)
        )
        self._conn.commit()
        return cur.rowcount

    def blacklist_remove(self, ip: str):
        ip = self.normalise_ip(ip)
        self._conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
        self._conn.commit()

    def blacklist_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]

    # -- strikes (bad SNI tracking) ------------------------------------------
    def strike_add(self, ip: str, sni: str):
        ip = self.normalise_ip(ip)
        self._conn.execute(
            "INSERT INTO strikes (ip, sni, created_at) VALUES (?, ?, ?)",
            (ip, sni, self._now()),
        )
        self._conn.commit()

    def strike_count(self, ip: str, window_seconds: int) -> int:
        """Count strikes for an IP within the last window_seconds."""
        ip = self.normalise_ip(ip)
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
        row = self._conn.execute(
            "SELECT COUNT(*) FROM strikes WHERE ip = ? AND created_at > ?",
            (ip, cutoff),
        ).fetchone()
        return row[0] if row else 0

    def strikes_cleanup(self, max_age_days: int = 30) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        cur = self._conn.execute("DELETE FROM strikes WHERE created_at < ?", (cutoff,))
        self._conn.commit()
        return cur.rowcount

    def close(self):
        if self._conn:
            self._conn.close()


# ---------------------------------------------------------------------------
# Port Knock Manager (uses IPDatabase)
# ---------------------------------------------------------------------------
class PortKnockManager:
    """Single-port knock: connect to knock_port → IP whitelisted via SQLite."""

    def __init__(self, knock_port: int, whitelist_ttl: int,
                 cleanup_interval: int, db: IPDatabase):
        self.knock_port = knock_port
        self.whitelist_ttl = whitelist_ttl
        self.cleanup_interval = cleanup_interval
        self.db = db
        self._cleanup_task: asyncio.Task | None = None

    async def start(self, host: str):
        server = await asyncio.start_server(
            self._handle_knock, host, self.knock_port,
            family=socket.AF_UNSPEC,
            flags=socket.AI_PASSIVE,
        )
        addrs = [s.getsockname() for s in server.sockets]
        logger.info("Port-knock listener on %s", addrs)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        return server

    async def _handle_knock(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info("peername")
        if peername:
            ip = IPDatabase.normalise_ip(peername[0])
            # Check if blacklisted first
            if self.db.blacklist_check(ip):
                logger.info("🚫  Knock from %s — BLACKLISTED, ignoring", ip)
            else:
                self.db.whitelist_add(ip, self.whitelist_ttl)
                if self.whitelist_ttl > 0:
                    logger.info("🔓  Knock from %s — whitelisted for %ds", ip, self.whitelist_ttl)
                else:
                    logger.info("🔓  Knock from %s — whitelisted permanently", ip)
        writer.close()
        await writer.wait_closed()

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(self.cleanup_interval)
            wl = self.db.whitelist_cleanup()
            bl = self.db.blacklist_cleanup()
            st = self.db.strikes_cleanup()
            if wl or bl or st:
                logger.info("Cleanup: %d whitelist, %d blacklist, %d strikes expired",
                            wl, bl, st)


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------
async def resolve_and_connect(
    host: str, port: int, prefer_ipv6: bool, timeout: float
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Resolve host (A+AAAA) and connect, respecting IPv4/IPv6 preference."""
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"Cannot resolve {host}")

    # Separate into v4 and v6
    v4 = [i for i in infos if i[0] == socket.AF_INET]
    v6 = [i for i in infos if i[0] == socket.AF_INET6]

    ordered = (v6 + v4) if prefer_ipv6 else (v4 + v6)
    if not ordered:
        ordered = infos

    last_exc: Exception | None = None
    for family, stype, proto, _canonname, sockaddr in ordered:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=sockaddr[0], port=sockaddr[1], family=family),
                timeout=timeout,
            )
            logger.debug("Connected to %s -> %s", host, sockaddr)
            return reader, writer
        except Exception as exc:
            last_exc = exc
            continue

    raise last_exc or OSError(f"Failed to connect to {host}:{port}")


async def connect_via_proxy(
    target_host: str, target_port: int,
    proxy_host: str, proxy_port: int,
    proxy_user: str | None, proxy_pass: str | None,
    prefer_ipv6: bool, timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Establish an HTTP CONNECT tunnel through an upstream proxy."""
    reader, writer = await resolve_and_connect(proxy_host, proxy_port, prefer_ipv6, timeout)

    # Build CONNECT request
    connect_line = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
    connect_line += f"Host: {target_host}:{target_port}\r\n"
    if proxy_user:
        cred = base64.b64encode(f"{proxy_user}:{proxy_pass or ''}".encode()).decode()
        connect_line += f"Proxy-Authorization: Basic {cred}\r\n"
    connect_line += "\r\n"

    writer.write(connect_line.encode())
    await writer.drain()

    # Read proxy response
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk:
            raise ConnectionError("Proxy closed connection before CONNECT response")
        response += chunk

    status_line = response.split(b"\r\n")[0].decode(errors="replace")
    if " 200 " not in status_line:
        writer.close()
        raise ConnectionError(f"Proxy CONNECT failed: {status_line}")

    logger.debug("HTTP CONNECT tunnel established via %s:%d -> %s:%d",
                 proxy_host, proxy_port, target_host, target_port)
    return reader, writer


# ---------------------------------------------------------------------------
# Bidirectional relay
# ---------------------------------------------------------------------------
async def relay(
    reader1: asyncio.StreamReader, writer1: asyncio.StreamWriter,
    reader2: asyncio.StreamReader, writer2: asyncio.StreamWriter,
    buffer_size: int,
):
    """Relay data bidirectionally between two streams until one side closes."""

    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
        try:
            while True:
                data = await src.read(buffer_size)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    t1 = asyncio.create_task(_pipe(reader1, writer2))
    t2 = asyncio.create_task(_pipe(reader2, writer1))
    await asyncio.gather(t1, t2, return_exceptions=True)


# ---------------------------------------------------------------------------
# SNI Proxy Server
# ---------------------------------------------------------------------------
class SNIProxyServer:
    """Main SNI proxy: listen, parse ClientHello, match domain, relay."""

    def __init__(self, config: dict):
        self.cfg = config
        self.domain_matcher = DomainMatcher(config.get("domains", []))

        # Network prefs
        net = config.get("network", {})
        self.prefer_ipv6: bool = net.get("prefer_ipv6", False)
        self.connect_timeout: float = net.get("connect_timeout", 10)
        self.buffer_size: int = net.get("relay_buffer_size", 8192)

        # Upstream proxy
        up = config.get("upstream_proxy", {})
        self.proxy_host: str = up.get("host", "") or ""
        self.proxy_port: int = up.get("port", 0) or 0
        self.proxy_user: str = up.get("username", "") or ""
        self.proxy_pass: str = up.get("password", "") or ""
        self.use_proxy: bool = bool(self.proxy_host and self.proxy_port)

        # SQLite database
        db_path = config.get("database", {}).get("path", "sniproxy.db")
        self.db = IPDatabase(db_path)

        # Auto-blacklist config
        bl = config.get("auto_blacklist", {})
        self.autoban_enabled: bool = bl.get("enabled", True)
        self.autoban_strikes: int = bl.get("strikes", 10)
        self.autoban_window: int = bl.get("window_seconds", 60)
        self.autoban_days: int = bl.get("ban_days", 7)

        # Port knock
        pk = config.get("port_knock", {})
        self.knock_enabled: bool = pk.get("enabled", False)
        self.knock_manager: PortKnockManager | None = None
        if self.knock_enabled:
            self.knock_manager = PortKnockManager(
                knock_port=pk.get("knock_port", 9999),
                whitelist_ttl=pk.get("whitelist_ttl", 3600),
                cleanup_interval=pk.get("cleanup_interval", 60),
                db=self.db,
            )

        # Stats
        self._total_connections = 0
        self._active_connections = 0

    async def start(self):
        listen_cfg = self.cfg.get("listen", {})
        host = listen_cfg.get("host", "0.0.0.0")
        port = listen_cfg.get("port", 443)

        # Start knock listener if enabled
        if self.knock_manager:
            await self.knock_manager.start(host)

        server = await asyncio.start_server(
            self._handle_client, host, port,
            family=socket.AF_UNSPEC,
            flags=socket.AI_PASSIVE,
        )
        addrs = [s.getsockname() for s in server.sockets]
        logger.info("SNI Proxy listening on %s", addrs)
        if self.use_proxy:
            logger.info("Upstream proxy: %s:%d", self.proxy_host, self.proxy_port)
        if self.knock_enabled:
            logger.info("Port-knock whitelist enabled (port %d, TTL %ds)",
                        self.knock_manager.knock_port, self.knock_manager.whitelist_ttl)
        else:
            logger.info("Port-knock whitelist DISABLED — all IPs allowed")
        if self.autoban_enabled:
            logger.info("Auto-blacklist ON: %d strikes in %ds → ban %d days",
                        self.autoban_strikes, self.autoban_window, self.autoban_days)
        logger.info("Domain rules: %d patterns loaded", len(self.domain_matcher._patterns))
        logger.info("Database: %s (whitelist=%d, blacklist=%d)",
                    self.db.db_path, self.db.whitelist_count(), self.db.blacklist_count())

        async with server:
            await server.serve_forever()

    # -- connection handler --------------------------------------------------
    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        peername = client_writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        client_ip = IPDatabase.normalise_ip(client_ip)
        self._total_connections += 1
        self._active_connections += 1
        conn_id = self._total_connections

        try:
            # 1. Blacklist check (always, regardless of knock setting)
            if self.db.blacklist_check(client_ip):
                logger.info("[#%d] 🚫  %s — BLACKLISTED, dropping", conn_id, client_ip)
                return

            # 2. Whitelist check
            if self.knock_enabled:
                if not self.db.whitelist_check(client_ip):
                    logger.info("[#%d] ❌  %s — not whitelisted, dropping", conn_id, client_ip)
                    return

            # 3. Read ClientHello (peek enough bytes)
            data = await asyncio.wait_for(client_reader.read(8192), timeout=self.connect_timeout)
            if not data:
                logger.debug("[#%d] Empty connection from %s", conn_id, client_ip)
                return

            # 4. Parse SNI
            hostname = parse_client_hello(data)
            if not hostname:
                logger.info("[#%d] ⚠️  %s — no SNI found, dropping", conn_id, client_ip)
                self._record_strike(client_ip, "(no SNI)")
                return

            # 5. Domain match
            if not self.domain_matcher.match(hostname):
                logger.info("[#%d] 🚫  %s -> %s — domain not allowed", conn_id, client_ip, hostname)
                self._record_strike(client_ip, hostname)
                return

            logger.info("[#%d] ✅  %s -> %s — proxying", conn_id, client_ip, hostname)

            # 6. Connect to target (directly or via proxy)
            target_port = 443
            try:
                if self.use_proxy:
                    upstream_reader, upstream_writer = await connect_via_proxy(
                        hostname, target_port,
                        self.proxy_host, self.proxy_port,
                        self.proxy_user, self.proxy_pass,
                        self.prefer_ipv6, self.connect_timeout,
                    )
                else:
                    upstream_reader, upstream_writer = await resolve_and_connect(
                        hostname, target_port,
                        self.prefer_ipv6, self.connect_timeout,
                    )
            except Exception as exc:
                logger.warning("[#%d] Failed to connect to %s: %s", conn_id, hostname, exc)
                return

            # 7. Forward the initial ClientHello data we already read
            upstream_writer.write(data)
            await upstream_writer.drain()

            # 8. Relay bidirectionally
            await relay(client_reader, client_writer, upstream_reader, upstream_writer, self.buffer_size)
            logger.debug("[#%d] Connection closed: %s -> %s", conn_id, client_ip, hostname)

        except asyncio.TimeoutError:
            logger.debug("[#%d] Timeout from %s", conn_id, client_ip)
        except Exception as exc:
            logger.debug("[#%d] Error from %s: %s", conn_id, client_ip, exc)
        finally:
            self._active_connections -= 1
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    def _record_strike(self, ip: str, sni: str):
        """Record a bad-SNI strike against an IP; auto-ban if threshold exceeded."""
        if not self.autoban_enabled:
            return
        self.db.strike_add(ip, sni)
        count = self.db.strike_count(ip, self.autoban_window)
        if count >= self.autoban_strikes:
            self.db.blacklist_add(ip, f"Auto-ban: {count} bad SNI in {self.autoban_window}s",
                                 self.autoban_days)
            logger.warning("🔨  AUTO-BANNED %s for %d days (%d strikes, last SNI: %s)",
                           ip, self.autoban_days, count, sni)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
def load_config(path: str) -> dict:
    """Load JSON config; fall back to defaults if file missing."""
    config_path = Path(path)
    if not config_path.exists():
        logger.warning("Config file not found: %s — using defaults", path)
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    return cfg


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Determine config path (CLI arg or default)
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    config = load_config(config_path)

    # Setup logging
    log_level = config.get("logging", {}).get("level", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Banner
    logger.info("=" * 60)
    logger.info("  SNI Proxy — starting")
    logger.info("  Config: %s", os.path.abspath(config_path))
    logger.info("=" * 60)

    proxy = SNIProxyServer(config)

    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("Shutting down…")


if __name__ == "__main__":
    main()
