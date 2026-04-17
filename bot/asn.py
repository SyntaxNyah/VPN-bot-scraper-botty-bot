"""
Bulk IP -> ASN enrichment via Team Cymru's free whois service.

Cymru's bulk-mode whois is purpose-built for exactly this: one TCP
connection, many IPs, pipe-delimited responses. No API key required.
Docs: https://team-cymru.com/community-services/ip-asn-mapping/
"""
from __future__ import annotations

import asyncio
import logging
import random
from collections import Counter
from dataclasses import dataclass

log = logging.getLogger(__name__)

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
CHUNK_SIZE = 2500           # IPs per connection
SAMPLE_CAP = 12000          # random sample size if the union is bigger
CONNECT_TIMEOUT = 15
READ_TIMEOUT = 60


@dataclass(frozen=True)
class AsnInfo:
    asn: int
    name: str
    country: str


async def _query_chunk(ips: list[str]) -> dict[str, AsnInfo]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(CYMRU_HOST, CYMRU_PORT),
            timeout=CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError) as e:
        log.warning("cymru connect failed: %s", e)
        return {}

    try:
        payload = "begin\nverbose\nnoheader\n" + "\n".join(ips) + "\nend\n"
        writer.write(payload.encode("ascii"))
        await writer.drain()

        raw = await asyncio.wait_for(reader.read(-1), timeout=READ_TIMEOUT)
    except (asyncio.TimeoutError, OSError) as e:
        log.warning("cymru read failed: %s", e)
        return {}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    out: dict[str, AsnInfo] = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn_s, ip, _prefix, cc, _reg, _alloc, name = parts[:7]
        if not asn_s.isdigit():
            continue
        try:
            out[ip] = AsnInfo(asn=int(asn_s), name=name or "UNKNOWN",
                              country=cc or "??")
        except ValueError:
            continue
    return out


async def enrich(ips: set[str]) -> dict[str, AsnInfo]:
    """Return {ip: AsnInfo}. Samples down to SAMPLE_CAP for giant sets."""
    if not ips:
        return {}
    pool = list(ips)
    if len(pool) > SAMPLE_CAP:
        pool = random.sample(pool, SAMPLE_CAP)

    chunks = [pool[i:i + CHUNK_SIZE] for i in range(0, len(pool), CHUNK_SIZE)]
    results = await asyncio.gather(*(_query_chunk(c) for c in chunks))
    merged: dict[str, AsnInfo] = {}
    for r in results:
        merged.update(r)
    return merged


def rank_asns(enriched: dict[str, AsnInfo], top: int | None = 10
              ) -> list[tuple[AsnInfo, int]]:
    """Return [(AsnInfo, hit_count), ...] sorted by hit count desc.

    Pass top=None to get the full ranking.
    """
    counter: Counter[int] = Counter()
    labels: dict[int, AsnInfo] = {}
    for info in enriched.values():
        counter[info.asn] += 1
        # keep whichever label we see first; all entries for one ASN share it
        labels.setdefault(info.asn, info)
    ranked = counter.most_common(top)
    return [(labels[asn], hits) for asn, hits in ranked]
