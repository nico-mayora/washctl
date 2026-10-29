"""Discover Candy appliances on the LAN via UDP broadcast on port 55555.

The washer periodically broadcasts a UDP packet. Bytes 60–92 contain ASCII
text; substring(1, 13) within that slice is the MAC address (12 hex chars,
no separators). The sender's IP is the appliance IP.
"""

import asyncio
import socket


UDP_PORT = 55555
MAC_OFFSET_START = 60
MAC_OFFSET_END = 92


def _normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()


def _extract_mac_from_packet(data: bytes) -> str | None:
    if len(data) < MAC_OFFSET_END:
        return None
    ascii_slice = data[MAC_OFFSET_START:MAC_OFFSET_END]
    try:
        text = ascii_slice.decode("ascii", errors="ignore")
    except Exception:
        return None
    # substring(1, 13) — 12 hex chars = MAC without separators
    if len(text) < 13:
        return None
    return text[1:13].lower()


def discover_sync(mac: str | None = None, timeout: float = 10.0) -> dict | None:
    """Listen for a UDP broadcast and return {"ip": ..., "mac": ...}, or None on timeout.

    If mac is given, only return a packet whose MAC matches (colon-stripped comparison).
    """
    target_mac = _normalize_mac(mac) if mac else None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.settimeout(timeout)
    sock.bind(("", UDP_PORT))

    try:
        while True:
            try:
                data, (sender_ip, _port) = sock.recvfrom(4096)
            except socket.timeout:
                return None
            pkt_mac = _extract_mac_from_packet(data)
            if pkt_mac is None:
                continue
            if target_mac and pkt_mac != target_mac:
                continue
            return {"ip": sender_ip, "mac": pkt_mac}
    finally:
        sock.close()


async def discover_async(mac: str | None = None, timeout: float = 10.0) -> dict | None:
    """Async wrapper around discover_sync."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, discover_sync, mac, timeout)


# ---- LAN scan fallback ----

def _get_local_subnets() -> list[str]:
    """Return /24 prefixes of non-loopback, non-virtual IPv4 interfaces."""
    import subprocess
    prefixes = []
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr"], text=True, timeout=5)
        for line in out.splitlines():
            parts = line.split()
            iface = parts[1] if len(parts) > 1 else ""
            # Skip loopback, Docker, and virtual bridge interfaces
            if any(iface.startswith(p) for p in ("lo", "docker", "br-", "veth", "virbr")):
                continue
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    addr = parts[i + 1].split("/")[0]
                    if not addr.startswith("127."):
                        octets = addr.split(".")
                        if len(octets) == 4:
                            prefixes.append(".".join(octets[:3]))
    except Exception:
        pass
    return prefixes or ["192.168.1"]


async def lan_scan(key: str, timeout_per_host: float = 2.0, progress=None) -> str | None:
    """Scan the local /24 for a Candy washer by trying http-read.json on each host.

    Returns the IP if found, None otherwise. `progress` is an optional callable(msg).
    """
    import httpx
    import json as _json

    prefixes = _get_local_subnets()
    if progress:
        progress(f"Scanning {len(prefixes)} subnet(s): {', '.join(p + '.0/24' for p in prefixes)}")

    async def _try_host(ip: str) -> str | None:
        url = f"http://{ip}/http-read.json?encrypted=1"
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(url, timeout=timeout_per_host)
                raw = r.text.strip()
                # XOR-decrypt with key
                key_bytes = key.encode("utf-8")
                hex_str = raw.upper()
                cipher = bytes(int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2))
                plain = bytes(c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(cipher))
                obj = _json.loads(plain.decode("utf-8", errors="replace"))
                if isinstance(obj, dict) and len(obj) > 0:
                    return ip
        except Exception:
            pass
        return None

    for prefix in prefixes:
        # Scan in batches of 25 to avoid exhausting file descriptors
        for batch_start in range(1, 255, 25):
            batch_end = min(batch_start + 25, 255)
            tasks = [_try_host(f"{prefix}.{i}") for i in range(batch_start, batch_end)]
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    return r
    return None
