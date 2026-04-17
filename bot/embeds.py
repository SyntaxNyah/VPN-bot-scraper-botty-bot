"""Discord embed builders."""
from __future__ import annotations

import datetime as dt

import discord

from .asn import AsnInfo
from .scrapers import FeedResult

COLOR_OK = 0x2ecc71
COLOR_WARN = 0xe67e22
COLOR_BAD = 0xe74c3c


def _trunc_field(value: str, limit: int = 1024) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 20] + "\n… (truncated)"


def build_summary_embed(results: list[FeedResult],
                        total_ips: int,
                        total_cidrs: int,
                        duration_s: float) -> discord.Embed:
    ok = [r for r in results if not r.error]
    failed = [r for r in results if r.error]

    color = COLOR_OK if not failed else (COLOR_WARN if ok else COLOR_BAD)
    embed = discord.Embed(
        title="VPN / Proxy / Abuse Blocklist — Refresh",
        description=(f"**{total_ips:,}** unique IPs and **{total_cidrs:,}** CIDR "
                     f"blocks across **{len(ok)}** feeds "
                     f"(scraped in {duration_s:.1f}s)."),
        color=color,
        timestamp=dt.datetime.now(dt.timezone.utc),
    )

    rows = []
    for r in sorted(ok, key=lambda x: x.count, reverse=True):
        rows.append(f"`{r.name:<20}` {r.count:>8,}")
    if rows:
        embed.add_field(
            name=f"Feeds ({len(ok)})",
            value=_trunc_field("\n".join(rows)),
            inline=False,
        )

    if failed:
        fail_rows = [f"`{r.name:<20}` {r.error}" for r in failed]
        embed.add_field(
            name=f"Failed feeds ({len(failed)})",
            value=_trunc_field("\n".join(fail_rows)),
            inline=False,
        )

    embed.set_footer(text="Sources: VPN Gate · X4BNet · FireHOL · Tor · "
                          "ProxyScrape · blocklist.de · IPsum · ET · Spamhaus · "
                          "Binary Defense · CINS")
    return embed


def build_asn_embed(ranked: list[tuple[AsnInfo, int]],
                    sample_size: int) -> discord.Embed:
    embed = discord.Embed(
        title="Top Abused ASNs",
        description=(f"Most frequently appearing ASNs across a sample of "
                     f"**{sample_size:,}** enriched IPs.\n"
                     f"Enriched via Team Cymru bulk whois."),
        color=COLOR_BAD,
        timestamp=dt.datetime.now(dt.timezone.utc),
    )

    if not ranked:
        embed.add_field(name="No data",
                        value="ASN enrichment returned no results.",
                        inline=False)
        return embed

    lines = []
    for i, (info, hits) in enumerate(ranked, start=1):
        pct = (hits / sample_size) * 100 if sample_size else 0
        name = (info.name[:55] + "…") if len(info.name) > 56 else info.name
        lines.append(
            f"`{i:>2}.` **AS{info.asn}** `{info.country}` — "
            f"{hits:,} hits ({pct:.1f}%)\n     {name}"
        )
    embed.add_field(name="Ranking", value=_trunc_field("\n".join(lines)),
                    inline=False)
    embed.set_footer(text="Block these ASNs at your edge to nuke the "
                          "long tail of VPN/proxy abuse.")
    return embed
