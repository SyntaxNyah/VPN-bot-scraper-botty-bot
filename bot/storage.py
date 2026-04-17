"""File-based blocklist "notepad" dumps."""
from __future__ import annotations

import datetime as dt
import os
import tempfile
from collections import Counter
from pathlib import Path

from .asn import AsnInfo


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".blocklist-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _sorted_ips(ips: set[str]) -> list[str]:
    return sorted(ips, key=lambda s: tuple(int(p) for p in s.split(".")))


def _format_asn_section(ranked_full: list[tuple[AsnInfo, int]],
                        sample_size: int, limit: int = 50) -> list[str]:
    if not ranked_full:
        return ["# (no ASN enrichment data available)"]
    lines = [
        f"# ASN abuse ranking (sample size: {sample_size:,})",
        f"# {'Rank':<5} {'ASN':<10} {'CC':<3} {'Hits':>8} {'%':>6}  Name",
    ]
    for i, (info, hits) in enumerate(ranked_full[:limit], start=1):
        pct = (hits / sample_size) * 100 if sample_size else 0
        lines.append(
            f"# {i:<5} AS{info.asn:<8} {info.country:<3} "
            f"{hits:>8,} {pct:>5.1f}%  {info.name}"
        )
    return lines


def write_all(
    blocklist_path: str,
    ips: set[str],
    cidrs: set[str],
    per_feed_counts: dict[str, int],
    ranked_full: list[tuple[AsnInfo, int]],
    asn_sample_size: int,
) -> dict[str, Path]:
    """
    Emit four files alongside `blocklist_path`:

      blocklist.txt           flat sorted IPv4, one per line
      blocklist.cidr.txt      CIDR ranges too large to expand
      blocklist_full.txt      combined mega-dump: ASN ranking + CIDRs + IPs
      asns.txt                full ASN abuse histogram (top 250)

    Returns a dict of logical-name -> Path.
    """
    ip_path = Path(blocklist_path)
    base = ip_path.with_suffix("") if ip_path.suffix else ip_path
    cidr_path = base.with_name(base.name + ".cidr.txt")
    full_path = base.with_name(base.name + "_full.txt")
    asn_path = base.with_name("asns.txt")

    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    sorted_ip_lines = _sorted_ips(ips)
    sorted_cidrs = sorted(cidrs)

    header = [
        f"# VPN/Proxy/Abuse blocklist — generated {ts}",
        f"# Unique IPs: {len(ips):,}  |  CIDRs: {len(cidrs):,}",
        f"# Feeds ({len(per_feed_counts)}):",
        *[f"#   {name:<24} {cnt:>10,}" for name, cnt in
          sorted(per_feed_counts.items(), key=lambda kv: -kv[1])],
        "",
    ]

    # 1) flat IP list
    _atomic_write(ip_path, "\n".join(header + sorted_ip_lines) + "\n")

    # 2) CIDR list
    _atomic_write(cidr_path, "\n".join(header + sorted_cidrs) + "\n")

    # 3) combined mega-dump: ASN ranking + CIDRs + IPs
    asn_section = _format_asn_section(ranked_full, asn_sample_size, limit=50)
    full_body = (
        header
        + asn_section
        + ["", f"# --- CIDR ranges ({len(sorted_cidrs):,}) ---"]
        + sorted_cidrs
        + ["", f"# --- IPv4 addresses ({len(sorted_ip_lines):,}) ---"]
        + sorted_ip_lines
    )
    _atomic_write(full_path, "\n".join(full_body) + "\n")

    # 4) full ASN histogram (top 250)
    asn_body = [
        f"# Top abused ASNs — generated {ts}",
        f"# Sample size: {asn_sample_size:,}",
        f"# {'Rank':<5} {'ASN':<10} {'CC':<3} {'Hits':>8} {'%':>6}  Name",
    ]
    for i, (info, hits) in enumerate(ranked_full[:250], start=1):
        pct = (hits / asn_sample_size) * 100 if asn_sample_size else 0
        asn_body.append(
            f"{i:<5} AS{info.asn:<8} {info.country:<3} "
            f"{hits:>8,} {pct:>5.1f}%  {info.name}"
        )
    _atomic_write(asn_path, "\n".join(asn_body) + "\n")

    return {
        "ips": ip_path,
        "cidrs": cidr_path,
        "full": full_path,
        "asns": asn_path,
    }
