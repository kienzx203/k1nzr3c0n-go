#!/usr/bin/env python3
"""Filter a public resolver list down to resolvers alive FROM THIS NETWORK.

Why: on flapping NATs (VMware NAT over Vietnamese ISP, bad cable days…) a big
chunk of any public resolver list is unreachable — mass-resolving through dead
resolvers silently drops live subdomains (observed: 685 candidates → 56 live
with an unfiltered 13k list on a NAT where 60% of resolvers were dead).

Usage:
    resolver_filter.py <resolvers_file> <output_file> [--max-probes N] [--threads N]

Output = trusted resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9…, plus the default-route
gateway when it answers DNS) + probed-alive resolvers from the input list.
Pure stdlib: minimal raw DNS A query over UDP, no dependencies.
"""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

TRUSTED = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
           "208.67.222.222", "208.67.220.220"]
PROBE_HOST = "dns.google"
TIMEOUT = 1.5


def _dns_query_bytes() -> bytes:
    """Minimal DNS query: A record for PROBE_HOST (recursion desired)."""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode()
        for label in PROBE_HOST.split(".")
    ) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A QCLASS=IN


_QUERY = _dns_query_bytes()


def _alive(resolver: str) -> bool:
    parts = resolver.split(":")
    ip = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 53
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.sendto(_QUERY, (ip, port))
        data, _ = s.recvfrom(4096)
        s.close()
        # Any DNS response with our tid counts (even NXDOMAIN = server alive)
        return len(data) >= 12 and data[0:2] == _QUERY[0:2]
    except OSError:
        return False


def _gateway() -> str | None:
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if f[1] == "00000000":  # default route
                    gw_hex = f[2]
                    return ".".join(
                        str(int(gw_hex[i:i + 2], 16)) for i in (6, 4, 2, 0)
                    )
    except OSError:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("resolvers_file")
    ap.add_argument("output_file")
    ap.add_argument("--max-probes", type=int, default=600,
                    help="max resolvers to probe from the input list")
    ap.add_argument("--threads", type=int, default=60)
    args = ap.parse_args()

    candidates: list[str] = []
    try:
        with open(args.resolvers_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                r = line.strip()
                if r and not r.startswith("#"):
                    candidates.append(r)
    except OSError as e:
        sys.stderr.write(f"[resolver_filter] cannot read {args.resolvers_file}: {e}\n")
        candidates = []

    if len(candidates) > args.max_probes:
        candidates = random.sample(candidates, args.max_probes)

    # Trusted first + gateway (the NAT's own DNS proxy is the most reliable)
    pool: list[str] = []
    gw = _gateway()
    if gw:
        pool.append(gw)
        sys.stderr.write(f"[resolver_filter] default gateway: {gw}\n")
    pool += [r for r in TRUSTED if r not in pool]

    sys.stderr.write(
        f"[resolver_filter] probing {len(candidates)} resolvers "
        f"({args.threads} threads)…\n")
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for r, ok in zip(candidates, ex.map(_alive, candidates)):
            if ok:
                alive.append(r)

    result = pool + [r for r in alive if r not in pool]
    with open(args.output_file, "w", encoding="utf-8") as fh:
        for r in result:
            fh.write(r + "\n")

    sys.stderr.write(
        f"[resolver_filter] kept {len(result)} resolvers "
        f"({len(alive)} alive from list + {len(result) - len(alive)} trusted/gateway)\n")
    print(f"resolvers: {len(result)} → {args.output_file}")


if __name__ == "__main__":
    main()
