"""Entry point for the VPN Blocker Discord bot."""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

import discord
from discord.ext import commands, tasks

from . import asn as asn_mod
from . import scrapers, storage
from .config import CONFIG
from .embeds import build_asn_embed, build_summary_embed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("vpn-blocker")


intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!vpn ", intents=intents, help_command=None)


async def run_refresh() -> tuple[discord.Embed, discord.Embed,
                                 list[discord.File]]:
    """Scrape every feed, enrich ASNs, dump files, build embeds."""
    t0 = time.monotonic()
    results = await scrapers.run_all(disabled=CONFIG.disabled_feeds)

    all_ips: set[str] = set()
    all_cidrs: set[str] = set()
    per_feed_counts: dict[str, int] = {}
    for r in results:
        if r.error:
            continue
        all_ips |= r.ips
        all_cidrs |= r.cidrs
        per_feed_counts[r.name] = r.count

    enriched = await asn_mod.enrich(all_ips)
    ranked_full = asn_mod.rank_asns(enriched, top=None)
    ranked_top = ranked_full[:10]
    log.info("enriched %d/%d IPs via Cymru; top ASN: %s",
             len(enriched), len(all_ips),
             ranked_top[0][0].name if ranked_top else "n/a")

    paths = storage.write_all(
        CONFIG.blocklist_path,
        all_ips,
        all_cidrs,
        per_feed_counts,
        ranked_full,
        asn_sample_size=len(enriched),
    )
    log.info("wrote %s",
             ", ".join(f"{k}={v.stat().st_size/1024:.0f}KiB"
                       for k, v in paths.items() if v.exists()))

    duration = time.monotonic() - t0
    summary = build_summary_embed(results, len(all_ips), len(all_cidrs),
                                  duration)
    asn_embed = build_asn_embed(ranked_top, sample_size=len(enriched))

    # Attach files up to Discord's default 25 MiB bot attachment cap.
    files: list[discord.File] = []
    max_bytes = 24 * 1024 * 1024
    for key in ("full", "asns", "cidrs"):
        p = paths.get(key)
        if p and p.exists() and p.stat().st_size <= max_bytes:
            files.append(discord.File(str(p), filename=p.name))
    return summary, asn_embed, files


async def send_refresh(channel: discord.abc.Messageable) -> None:
    try:
        summary, asn_embed, files = await run_refresh()
    except Exception:  # noqa: BLE001
        log.exception("refresh failed")
        await channel.send("⚠️ Blocklist refresh failed — check logs.")
        return
    await channel.send(embeds=[summary, asn_embed], files=files)


@tasks.loop(minutes=CONFIG.refresh_minutes)
async def scheduled_refresh() -> None:
    channel = bot.get_channel(CONFIG.channel_id)
    if channel is None:
        try:
            channel = await bot.fetch_channel(CONFIG.channel_id)
        except discord.DiscordException as e:
            log.error("cannot resolve channel %s: %s", CONFIG.channel_id, e)
            return
    await send_refresh(channel)


@scheduled_refresh.before_loop
async def _before_loop() -> None:
    await bot.wait_until_ready()


@bot.event
async def on_ready() -> None:
    log.info("logged in as %s (id=%s)", bot.user, bot.user.id if bot.user else "?")
    if not scheduled_refresh.is_running():
        scheduled_refresh.start()


@bot.command(name="refresh")
@commands.has_permissions(manage_guild=True)
async def cmd_refresh(ctx: commands.Context) -> None:
    """Force an immediate blocklist refresh."""
    await ctx.send("🔄 Refreshing blocklists — this takes ~30-60s.")
    await send_refresh(ctx.channel)


@bot.command(name="status")
async def cmd_status(ctx: commands.Context) -> None:
    p = Path(CONFIG.blocklist_path)
    if not p.exists():
        await ctx.send("No blocklist written yet.")
        return
    stat = p.stat()
    await ctx.send(
        f"Blocklist `{p.name}` — {stat.st_size / 1024:.1f} KiB, "
        f"refresh every {CONFIG.refresh_minutes} min."
    )


@cmd_refresh.error
async def _refresh_err(ctx: commands.Context, error: Exception) -> None:
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You need `Manage Server` to force a refresh.")
    else:
        raise error


def main() -> None:
    CONFIG.validate()
    bot.run(CONFIG.token, log_handler=None)


if __name__ == "__main__":
    main()
