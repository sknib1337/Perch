"""
Minimal mDNS responder (RFC 6762) for `perch share --mdns` -- stdlib only.

Gives teammates a name instead of a raw IP: `web.local` resolves via multicast DNS,
which needs no admin rights, no hosts-file edits, and no DNS server. It is a
FALLBACK by design: mDNS only serves `*.local` names (no wildcards), and corporate
networks commonly block it across VLANs/APs, which is why `perch share` leads with
the plain LAN URL and Tailscale, and offers this behind an explicit --mdns flag
(see docs/RESEARCH_windows-intranet-sharing.md).

The packet encode/parse half is pure (no sockets) so every decision is
offline-testable; `respond_forever` is the thin socket loop around it. Everything
malformed fails closed: a packet we cannot parse, a response (not a query), or a
name we do not announce simply gets no answer.
"""

from __future__ import annotations

import socket
import struct

MDNS_ADDR, MDNS_PORT = "224.0.0.251", 5353
TTL = 120                      # short: a laptop's share should age out quickly
_A, _ANY, _IN = 1, 255, 1
_CACHE_FLUSH = 0x8001          # class IN with the mDNS cache-flush bit


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError(f"bad DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(data: bytes, off: int) -> "tuple[str, int]":
    """Decode an uncompressed QNAME; queries on the wire use plain labels.
    Compression pointers are rejected (fail closed) -- we answer queries, we do
    not parse arbitrary answers."""
    labels = []
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        n = data[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            raise ValueError("compressed name in query")
        off += 1
        labels.append(data[off:off + n].decode("ascii", "replace"))
        off += n


def answer(query: bytes, names: dict) -> "bytes | None":
    """The multicast answer for one query packet, or None when it asks about
    nothing we announce. `names` maps lowercase 'host.local' -> IPv4 string."""
    try:
        if len(query) < 12:
            return None
        _, flags, qd, _, _, _ = struct.unpack("!6H", query[:12])
        if flags & 0x8000:                      # a response, not a query
            return None
        off = 12
        matches: list[tuple[str, str]] = []
        for _ in range(qd):
            qname, off = decode_name(query, off)
            if off + 4 > len(query):
                return None
            qtype, qclass = struct.unpack("!2H", query[off:off + 4])
            off += 4
            ip = names.get(qname.lower())
            if ip and qtype in (_A, _ANY) and (qclass & 0x7FFF) == _IN:
                matches.append((qname, ip))
        if not matches:
            return None
        head = struct.pack("!6H", 0, 0x8400, 0, len(matches), 0, 0)
        body = b""
        for qname, ip in matches:
            body += (encode_name(qname)
                     + struct.pack("!HHIH", _A, _CACHE_FLUSH, TTL, 4)
                     + socket.inet_aton(ip))
        return head + body
    except (ValueError, OSError):
        return None                             # malformed input: no answer, ever


def respond_forever(names: dict, stop=None) -> None:
    """Foreground announcer: bind 5353, join the mDNS group, answer A queries for
    our names until interrupted (or until `stop()` returns True, for tests).
    Raises OSError when the port/group is unavailable so the CLI can say so."""
    names = {k.lower(): v for k, v in names.items()}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", MDNS_PORT))
    mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.settimeout(1.0)
    try:
        while stop is None or not stop():
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            resp = answer(data, names)
            if resp:
                s.sendto(resp, (MDNS_ADDR, MDNS_PORT))
    finally:
        s.close()
