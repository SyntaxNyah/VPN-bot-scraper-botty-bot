"""
Scrapers for free VPN / proxy / malicious-IP feeds.

Every feed returns a set of IPv4 addresses. CIDR ranges are expanded for /24
or smaller; larger blocks are tracked separately so the blocklist file can
also emit CIDRs without exploding into millions of entries.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

import aiohttp

log = logging.getLogger(__name__)

USER_AGENT = "VPN-Blocker-Bot/1.0 (+https://github.com/)"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=45)
MAX_CIDR_EXPAND_PREFIX = 24  # only expand /24 or smaller to individual IPs

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")


@dataclass
class FeedResult:
    name: str
    ips: set[str] = field(default_factory=set)
    cidrs: set[str] = field(default_factory=set)
    error: str | None = None

    @property
    def count(self) -> int:
        return len(self.ips) + len(self.cidrs)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
        resp.raise_for_status()
        return await resp.text(errors="replace")


def _valid_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified or ip.is_link_local)


def _ingest_cidr(cidr: str, ips: set[str], cidrs: set[str]) -> None:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return
    if net.prefixlen >= MAX_CIDR_EXPAND_PREFIX:
        for host in net.hosts():
            s = str(host)
            if _valid_public_ip(s):
                ips.add(s)
    else:
        cidrs.add(str(net))


def _parse_plain_list(text: str) -> tuple[set[str], set[str]]:
    ips: set[str] = set()
    cidrs: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        # tolerate "ip:port", "ip,something", whitespace-separated fields
        token = line.split()[0].split(",")[0].split("|")[0].strip()
        if "/" in token:
            _ingest_cidr(token, ips, cidrs)
            continue
        bare = token.split(":")[0]
        if _valid_public_ip(bare):
            ips.add(bare)
            continue
        # fallback: pick the first IP/CIDR anywhere on the line
        m = CIDR_RE.search(line)
        if m:
            _ingest_cidr(m.group(0), ips, cidrs)
            continue
        m = IP_RE.search(line)
        if m and _valid_public_ip(m.group(0)):
            ips.add(m.group(0))
    return ips, cidrs


# ---------------------------------------------------------------------------
# Individual feed implementations
# ---------------------------------------------------------------------------

async def scrape_vpngate(session: aiohttp.ClientSession) -> FeedResult:
    """VPN Gate public CSV. Column 2 is the IP."""
    url = "https://www.vpngate.net/api/iphone/"
    text = await _fetch_text(session, url)
    ips: set[str] = set()
    for row in text.splitlines():
        if not row or row.startswith("*") or row.startswith("#"):
            continue
        parts = row.split(",")
        if len(parts) < 3:
            continue
        ip = parts[1].strip()
        if _valid_public_ip(ip):
            ips.add(ip)
    return FeedResult("vpngate", ips=ips)


async def scrape_x4bnet_vpn(session: aiohttp.ClientSession) -> FeedResult:
    """X4BNet aggregated commercial-VPN IP list (NordVPN, ExpressVPN, PIA, etc.)."""
    url = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("x4bnet_vpn", ips=ips, cidrs=cidrs)


async def scrape_x4bnet_datacenter(session: aiohttp.ClientSession) -> FeedResult:
    """X4BNet datacenter ranges — heavy with abused hosting ASNs."""
    url = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("x4bnet_datacenter", ips=ips, cidrs=cidrs)


async def scrape_firehol_anonymous(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://iplists.firehol.org/files/firehol_anonymous.netset"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("firehol_anonymous", ips=ips, cidrs=cidrs)


async def scrape_firehol_level1(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://iplists.firehol.org/files/firehol_level1.netset"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("firehol_level1", ips=ips, cidrs=cidrs)


async def scrape_firehol_proxies(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://iplists.firehol.org/files/firehol_proxies.netset"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("firehol_proxies", ips=ips, cidrs=cidrs)


async def scrape_tor_exits(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://check.torproject.org/torbulkexitlist"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("tor", ips=ips, cidrs=cidrs)


async def scrape_dan_tor(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://www.dan.me.uk/torlist/?exit"
    try:
        text = await _fetch_text(session, url)
    except aiohttp.ClientResponseError as e:
        # dan.me.uk rate-limits aggressively; surface but don't fail whole run
        return FeedResult("dan_tor", error=f"HTTP {e.status}")
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("dan_tor", ips=ips, cidrs=cidrs)


async def _scrape_proxyscrape(session: aiohttp.ClientSession, proto: str) -> FeedResult:
    url = (
        "https://api.proxyscrape.com/v2/?request=displayproxies"
        f"&protocol={proto}&timeout=10000&country=all&ssl=all&anonymity=all"
    )
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult(f"proxyscrape_{proto}", ips=ips, cidrs=cidrs)


async def scrape_proxyscrape_http(session): return await _scrape_proxyscrape(session, "http")
async def scrape_proxyscrape_socks4(session): return await _scrape_proxyscrape(session, "socks4")
async def scrape_proxyscrape_socks5(session): return await _scrape_proxyscrape(session, "socks5")


async def scrape_blocklist_de(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://lists.blocklist.de/lists/all.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("blocklist_de", ips=ips, cidrs=cidrs)


async def scrape_ipsum(session: aiohttp.ClientSession) -> FeedResult:
    """stamparm/ipsum — aggregated from ~30 sources, level 3+ = seen on multiple lists."""
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("ipsum_l3", ips=ips, cidrs=cidrs)


async def scrape_et_compromised(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("et_compromised", ips=ips, cidrs=cidrs)


async def scrape_spamhaus_drop(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://www.spamhaus.org/drop/drop.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("spamhaus_drop", ips=ips, cidrs=cidrs)


async def scrape_spamhaus_edrop(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://www.spamhaus.org/drop/edrop.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("spamhaus_edrop", ips=ips, cidrs=cidrs)


async def scrape_binarydefense(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://www.binarydefense.com/banlist.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("binarydefense", ips=ips, cidrs=cidrs)


async def scrape_cinsscore(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://cinsscore.com/list/ci-badguys.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("cinsscore", ips=ips, cidrs=cidrs)


# ---------------------------------------------------------------------------
# Registry + runner
# ---------------------------------------------------------------------------

ScraperFn = Callable[[aiohttp.ClientSession], "asyncio.Future[FeedResult]"]

SCRAPERS: dict[str, ScraperFn] = {
    "vpngate": scrape_vpngate,
    "x4bnet_vpn": scrape_x4bnet_vpn,
    "x4bnet_datacenter": scrape_x4bnet_datacenter,
    "firehol_anonymous": scrape_firehol_anonymous,
    "firehol_proxies": scrape_firehol_proxies,
    "firehol_level1": scrape_firehol_level1,
    "tor": scrape_tor_exits,
    "dan_tor": scrape_dan_tor,
    "proxyscrape_http": scrape_proxyscrape_http,
    "proxyscrape_socks4": scrape_proxyscrape_socks4,
    "proxyscrape_socks5": scrape_proxyscrape_socks5,
    "blocklist_de": scrape_blocklist_de,
    "ipsum_l3": scrape_ipsum,
    "et_compromised": scrape_et_compromised,
    "spamhaus_drop": scrape_spamhaus_drop,
    "spamhaus_edrop": scrape_spamhaus_edrop,
    "binarydefense": scrape_binarydefense,
    "cinsscore": scrape_cinsscore,
}


async def run_all(disabled: Iterable[str] = ()) -> list[FeedResult]:
    disabled_set = {d.lower() for d in disabled}
    enabled = [(name, fn) for name, fn in SCRAPERS.items() if name not in disabled_set]

    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain, */*"}
    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        async def _safe(name: str, fn: ScraperFn) -> FeedResult:
            try:
                return await fn(session)
            except Exception as e:  # noqa: BLE001 - we want to record every failure
                log.warning("feed %s failed: %s", name, e)
                return FeedResult(name, error=f"{type(e).__name__}: {e}")

        return await asyncio.gather(*[_safe(n, f) for n, f in enabled])
