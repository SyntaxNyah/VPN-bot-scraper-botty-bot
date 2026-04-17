# VPN Blocker — Discord Bot

The ultimate free VPN / proxy / abuse IP scraper, running as a Discord bot.

Every ~90 minutes (configurable) it:

1. Scrapes **18+ free threat-intel feeds** in parallel.
2. Dedupes & validates every IPv4 (rejects RFC1918, loopback, multicast, etc.).
3. Writes a flat `blocklist.txt` (one IP per line) plus `blocklist.txt.cidr.txt`
   for larger CIDR ranges — drop either into `iptables`, `ipset`, Cloudflare
   WAF, fail2ban, pfSense, Nginx `deny`, etc.
4. Enriches a sample of the IPs with **Team Cymru bulk whois** to rank the
   **most abused ASNs**.
5. Posts two embeds to your Discord channel: a refresh summary + the top-10
   abused ASNs. Files are attached when small enough.

## Feeds

| Category | Source |
|---|---|
| Free VPN servers | VPN Gate public CSV |
| Commercial VPN ranges | X4BNet (NordVPN, ExpressVPN, PIA, Surfshark, etc.) |
| Datacenter ranges | X4BNet datacenter list |
| Aggregated anonymous/proxies | FireHOL `firehol_anonymous`, `firehol_proxies`, `firehol_level1` |
| Tor exits | `check.torproject.org` bulk list, `dan.me.uk` |
| Open proxies | ProxyScrape HTTP / SOCKS4 / SOCKS5 |
| Brute-force / abuse | blocklist.de, Binary Defense, CINS Army |
| Compromised hosts | Emerging Threats, stamparm/ipsum (level 3+) |
| Spam / hijacked ranges | Spamhaus DROP, EDROP |

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
| `BLOCKLIST_PATH` | `blocklist.txt` | Flat-list output path. |
| `DISABLED_FEEDS` | — | Comma-separated feed names to skip, e.g. `tor,dan_tor`. |

Valid feed names match the keys in `bot/scrapers.py::SCRAPERS`.

## Intended use

Defensive. Use it to deny abuse traffic hitting your services — forums,
game servers, APIs, login endpoints. Don't use any of these lists to target
or harass individual users; they're noisy and false positives happen
(especially on residential-ISP recycled IPs and Tor exits).

## License

MIT.
