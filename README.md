# VPN Blocker — Discord Bot

The ultimate free VPN / proxy / abuse IP scraper, running as a Discord bot.

Every ~90 minutes (configurable) it:

1. Scrapes **47 free threat-intel feeds** in parallel.
2. Dedupes & validates every IPv4 (rejects RFC1918, loopback, multicast, etc.).
3. Enriches a sample of the IPs with **Team Cymru bulk whois** to rank the
   most abused ASNs.
4. Writes **four files** to disk:
    - `blocklist.txt` — flat sorted IPs, one per line.
    - `blocklist.cidr.txt` — CIDR blocks too large to expand.
    - `blocklist_full.txt` — **mega-dump**: ASN abuse ranking header, then CIDRs,
      then every IP.
    - `asns.txt` — top 250 abused ASNs with country + hit-count + percentage.
5. Posts two embeds to your Discord channel (refresh summary + top-10 ASNs)
   and attaches the dump files (up to 25 MiB per file, Discord's bot cap).

## Feeds (47)

| Category | Sources |
|---|---|
| Free VPN servers | VPN Gate public CSV |
| Commercial VPN public APIs | Mullvad, ProtonVPN, Fission Relays |
| Commercial VPN ranges | X4BNet (NordVPN, ExpressVPN, PIA, Surfshark, CyberGhost…) |
| Datacenter ranges | X4BNet datacenter list |
| Tor exits | `check.torproject.org` bulk list, `dan.me.uk` |
| FireHOL aggregates | `firehol_anonymous`, `firehol_proxies`, `firehol_level1`, `cruzit`, `bruteforceblocker` |
| Open proxies — ProxyScrape | HTTP, SOCKS4, SOCKS5 |
| Open proxies — TheSpeedX | HTTP, SOCKS4, SOCKS5 |
| Open proxies — MonoSans | HTTP, SOCKS4, SOCKS5 |
| Open proxies — Roosterkid | HTTPS, SOCKS4, SOCKS5 |
| Open proxies — NullSecure | aggregated HTTP list |
| Brute-force / attackers | blocklist.de, GreenSnow, DShield, MyIP.ms, AlienVault reputation, Binary Defense, CINS Army, Emerging Threats, duggytuxy botnets |
| Malware / C2 | abuse.ch Feodo Tracker, SSLBL, ThreatFox, montysecurity C2-Tracker |
| Aggregated multi-source | IPsum level 2 + 3, Maltrail mass-scanner + bruteforcer, BlocklistProject abuse + ransomware |
| Spam / hijacked | Spamhaus DROP, EDROP |

All sources are free and require no API key.

## Setup

```bash
git clone <repo>
cd VPN-bot-scraper-botty-bot
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env: fill in DISCORD_TOKEN and DISCORD_CHANNEL_ID
python -m bot.main
```

### Discord application

1. Create an app at <https://discord.com/developers/applications>.
2. Add a Bot, copy its token into `DISCORD_TOKEN`.
3. Invite with scopes `bot` + `applications.commands` and permissions
   `Send Messages`, `Attach Files`, `Embed Links`, `Read Message History`.
4. Paste the target channel ID into `DISCORD_CHANNEL_ID` (Developer Mode →
   right-click channel → Copy ID).

### Commands

| Command | Who | What |
|---|---|---|
| `!vpn refresh` | Manage Server | Force an immediate refresh. |
| `!vpn status` | Anyone | Show blocklist size + refresh interval. |

## Configuration

All via environment variables / `.env`:

| Var | Default | Notes |
|---|---|---|
| `DISCORD_TOKEN` | — | Required. |
| `DISCORD_CHANNEL_ID` | — | Required. |
| `REFRESH_MINUTES` | `90` | Min 30, to respect feed publishers. |
| `BLOCKLIST_PATH` | `blocklist.txt` | Base path; the other three files are written alongside it. |
| `DISABLED_FEEDS` | — | Comma-separated feed names to skip, e.g. `tor,dan_tor`. |

Valid feed names match the keys in `bot/scrapers.py::SCRAPERS`.

## Intended use

Defensive. Use it to deny abuse traffic hitting your services — forums,
game servers, APIs, login endpoints. Don't use any of these lists to target
or harass individual users; they're noisy and false positives happen
(especially on residential-ISP recycled IPs and Tor exits).

## License

MIT.
