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

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=120, connect=20, sock_read=90)
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

async def _fetch_text(session: aiohttp.ClientSession, url: str,
                      retries: int = 2) -> str:
    """GET with one automatic retry on transient timeouts or 5xx."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
                if resp.status >= 500 and attempt < retries:
                    raise aiohttp.ClientResponseError(
                        resp.request_info, resp.history,
                        status=resp.status, message=resp.reason or "")
                resp.raise_for_status()
                return await resp.text(errors="replace")
        except (asyncio.TimeoutError, aiohttp.ClientConnectionError,
                aiohttp.ClientResponseError) as e:
            last = e
            if attempt >= retries:
                break
            await asyncio.sleep(2 ** attempt)
    assert last is not None
    raise last


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


# --- abuse.ch family ------------------------------------------------------

async def scrape_feodotracker(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("feodotracker", ips=ips, cidrs=cidrs)


async def scrape_sslbl(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("sslbl", ips=ips, cidrs=cidrs)


async def scrape_threatfox(session: aiohttp.ClientSession) -> FeedResult:
    """ThreatFox recent IP:port IOCs (CSV). Column 3 is the IOC."""
    url = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"
    text = await _fetch_text(session, url)
    ips: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) < 4:
            continue
        ioc = parts[2]
        bare = ioc.split(":")[0]
        if _valid_public_ip(bare):
            ips.add(bare)
    return FeedResult("threatfox", ips=ips)


# --- attacker / scanner feeds --------------------------------------------

async def scrape_greensnow(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://blocklist.greensnow.co/greensnow.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("greensnow", ips=ips, cidrs=cidrs)


async def scrape_dshield(session: aiohttp.ClientSession) -> FeedResult:
    """SANS ISC top attacking /24s — returns CIDRs, mostly."""
    url = "https://www.dshield.org/block.txt"
    text = await _fetch_text(session, url)
    ips: set[str] = set()
    cidrs: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.lower().startswith("start"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        start, _end, netmask = fields[0], fields[1], fields[2]
        if netmask.isdigit() and _valid_public_ip(start):
            _ingest_cidr(f"{start}/{netmask}", ips, cidrs)
    return FeedResult("dshield", ips=ips, cidrs=cidrs)


async def scrape_myip_ms(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://myip.ms/files/blacklist/general/latest_blacklist.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("myip_ms", ips=ips, cidrs=cidrs)


async def scrape_alienvault(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://reputation.alienvault.com/reputation.generic"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("alienvault", ips=ips, cidrs=cidrs)


# --- stamparm family ------------------------------------------------------

async def scrape_ipsum_l2(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("ipsum_l2", ips=ips, cidrs=cidrs)


async def scrape_maltrail_mass_scanner(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("maltrail_mass_scanner", ips=ips, cidrs=cidrs)


async def scrape_maltrail_bruteforcer(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/bruteforcer.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("maltrail_bruteforcer", ips=ips, cidrs=cidrs)


# --- blocklistproject -----------------------------------------------------

async def scrape_blp_abuse(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse-ips.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("blp_abuse", ips=ips, cidrs=cidrs)


async def scrape_blp_ransomware(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware-ips.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("blp_ransomware", ips=ips, cidrs=cidrs)


# --- open-proxy aggregators ----------------------------------------------

async def _scrape_thespeedx(session: aiohttp.ClientSession, proto: str) -> FeedResult:
    url = f"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/{proto}.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult(f"thespeedx_{proto}", ips=ips, cidrs=cidrs)


async def scrape_thespeedx_http(s): return await _scrape_thespeedx(s, "http")
async def scrape_thespeedx_socks4(s): return await _scrape_thespeedx(s, "socks4")
async def scrape_thespeedx_socks5(s): return await _scrape_thespeedx(s, "socks5")


async def _scrape_monosans(session: aiohttp.ClientSession, proto: str) -> FeedResult:
    url = f"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/{proto}.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult(f"monosans_{proto}", ips=ips, cidrs=cidrs)


async def scrape_monosans_http(s): return await _scrape_monosans(s, "http")
async def scrape_monosans_socks4(s): return await _scrape_monosans(s, "socks4")
async def scrape_monosans_socks5(s): return await _scrape_monosans(s, "socks5")


async def _scrape_roosterkid(session: aiohttp.ClientSession, proto: str) -> FeedResult:
    url = f"https://raw.githubusercontent.com/roosterkid/openproxylist/main/{proto}_RAW.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult(f"roosterkid_{proto.lower()}", ips=ips, cidrs=cidrs)


async def scrape_roosterkid_https(s): return await _scrape_roosterkid(s, "HTTPS")
async def scrape_roosterkid_socks4(s): return await _scrape_roosterkid(s, "SOCKS4")
async def scrape_roosterkid_socks5(s): return await _scrape_roosterkid(s, "SOCKS5")


# --- commercial VPN public APIs ------------------------------------------

async def scrape_mullvad(session: aiohttp.ClientSession) -> FeedResult:
    """Mullvad publishes its full relay list as JSON."""
    url = "https://api.mullvad.net/www/relays/all/"
    async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
        resp.raise_for_status()
        data = await resp.json(content_type=None)
    ips: set[str] = set()
    for relay in data if isinstance(data, list) else []:
        ip = relay.get("ipv4_addr_in") if isinstance(relay, dict) else None
        if ip and _valid_public_ip(ip):
            ips.add(ip)
    return FeedResult("mullvad", ips=ips)


async def scrape_protonvpn(session: aiohttp.ClientSession) -> FeedResult:
    """ProtonVPN publishes its logical server list as JSON.

    The endpoint requires a few app-version headers or it returns 400.
    """
    url = "https://api.protonmail.ch/vpn/logicals"
    headers = {
        "x-pm-appversion": "LinuxVPN_4.0.0",
        "x-pm-apiversion": "3",
        "Accept": "application/vnd.protonmail.v1+json",
    }
    async with session.get(url, headers=headers,
                           timeout=REQUEST_TIMEOUT) as resp:
        resp.raise_for_status()
        data = await resp.json(content_type=None)
    ips: set[str] = set()
    for logical in (data or {}).get("LogicalServers", []):
        for server in logical.get("Servers", []) or []:
            for key in ("EntryIP", "ExitIP"):
                ip = server.get(key)
                if ip and _valid_public_ip(ip):
                    ips.add(ip)
    return FeedResult("protonvpn", ips=ips)


# --- more community lists -------------------------------------------------

async def scrape_duggytuxy_botnets(session: aiohttp.ClientSession) -> FeedResult:
    url = ("https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/"
           "main/botnets_zombies_scanner_spam_ips.txt")
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("duggytuxy_botnets", ips=ips, cidrs=cidrs)


async def scrape_c2_tracker(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("c2_tracker", ips=ips, cidrs=cidrs)


async def scrape_cruzit(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://iplists.firehol.org/files/cruzit_web_attacks.ipset"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("cruzit", ips=ips, cidrs=cidrs)


async def scrape_bruteforce_rules(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://iplists.firehol.org/files/bruteforceblocker.ipset"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("bruteforceblocker", ips=ips, cidrs=cidrs)


async def scrape_nullsecure(session: aiohttp.ClientSession) -> FeedResult:
    url = ("https://raw.githubusercontent.com/NullSecure/All-Proxies-Aggregator/"
           "refs/heads/main/http.txt")
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("nullsecure", ips=ips, cidrs=cidrs)


async def scrape_fissionrelays_vpn(session: aiohttp.ClientSession) -> FeedResult:
    url = "https://lists.fissionrelays.net/vpn/ip/all.txt"
    text = await _fetch_text(session, url)
    ips, cidrs = _parse_plain_list(text)
    return FeedResult("fissionrelays_vpn", ips=ips, cidrs=cidrs)


# ---------------------------------------------------------------------------
# Registry + runner
# ---------------------------------------------------------------------------

ScraperFn = Callable[[aiohttp.ClientSession], "asyncio.Future[FeedResult]"]

SCRAPERS: dict[str, ScraperFn] = {
    # VPN / datacenter
    "vpngate": scrape_vpngate,
    "x4bnet_vpn": scrape_x4bnet_vpn,
    "x4bnet_datacenter": scrape_x4bnet_datacenter,
    "mullvad": scrape_mullvad,
    "protonvpn": scrape_protonvpn,
    # Tor
    "tor": scrape_tor_exits,
    "dan_tor": scrape_dan_tor,
    # FireHOL aggregates
    "firehol_anonymous": scrape_firehol_anonymous,
    "firehol_proxies": scrape_firehol_proxies,
    "firehol_level1": scrape_firehol_level1,
    "cruzit": scrape_cruzit,
    "bruteforceblocker": scrape_bruteforce_rules,
    # Open proxies
    "proxyscrape_http": scrape_proxyscrape_http,
    "proxyscrape_socks4": scrape_proxyscrape_socks4,
    "proxyscrape_socks5": scrape_proxyscrape_socks5,
    "thespeedx_http": scrape_thespeedx_http,
    "thespeedx_socks4": scrape_thespeedx_socks4,
    "thespeedx_socks5": scrape_thespeedx_socks5,
    "monosans_http": scrape_monosans_http,
    "monosans_socks4": scrape_monosans_socks4,
    "monosans_socks5": scrape_monosans_socks5,
    "roosterkid_https": scrape_roosterkid_https,
    "roosterkid_socks4": scrape_roosterkid_socks4,
    "roosterkid_socks5": scrape_roosterkid_socks5,
    "nullsecure": scrape_nullsecure,
    # Attacker / brute-force / abuse
    "blocklist_de": scrape_blocklist_de,
    "greensnow": scrape_greensnow,
    "dshield": scrape_dshield,
    "myip_ms": scrape_myip_ms,
    "alienvault": scrape_alienvault,
    "binarydefense": scrape_binarydefense,
    "cinsscore": scrape_cinsscore,
    "et_compromised": scrape_et_compromised,
    "duggytuxy_botnets": scrape_duggytuxy_botnets,
    # Malware / C2
    "feodotracker": scrape_feodotracker,
    "sslbl": scrape_sslbl,
    "threatfox": scrape_threatfox,
    "c2_tracker": scrape_c2_tracker,
    # Aggregated / multi-source
    "ipsum_l3": scrape_ipsum,
    "ipsum_l2": scrape_ipsum_l2,
    "maltrail_mass_scanner": scrape_maltrail_mass_scanner,
    "maltrail_bruteforcer": scrape_maltrail_bruteforcer,
    "blp_abuse": scrape_blp_abuse,
    "blp_ransomware": scrape_blp_ransomware,
    # Spam / hijacked
    "spamhaus_drop": scrape_spamhaus_drop,
    "spamhaus_edrop": scrape_spamhaus_edrop,
}


async def run_all(disabled: Iterable[str] = ()) -> list[FeedResult]:
    disabled_set = {d.lower() for d in disabled}
    enabled = [(name, fn) for name, fn in SCRAPERS.items() if name not in disabled_set]

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/plain, text/csv, application/json, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    connector = aiohttp.TCPConnector(
        limit=64, limit_per_host=4, ttl_dns_cache=300,
    )
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        async def _safe(name: str, fn: ScraperFn) -> FeedResult:
            try:
                return await fn(session)
            except Exception as e:  # noqa: BLE001 - we want to record every failure
                log.warning("feed %s failed: %s", name, e)
                return FeedResult(name, error=f"{type(e).__name__}: {e}")

        return await asyncio.gather(*[_safe(n, f) for n, f in enabled])
