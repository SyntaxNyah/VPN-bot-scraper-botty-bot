"""File-based blocklist "notepad" dumps."""
from __future__ import annotations

import datetime as dt
import os
import tempfile
from pathlib import Path


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


def write_blocklist(path: str, ips: set[str], cidrs: set[str],
                    per_feed_counts: dict[str, int]) -> tuple[Path, Path]:
    """
    Writes two files alongside `path`:
      - <path>                     flat sorted list of bare IPs
      - <path>.cidr.txt            CIDR blocks that were too large to expand

    Returns (ip_path, cidr_path).
    """
    ip_path = Path(path)
    cidr_path = ip_path.with_suffix(ip_path.suffix + ".cidr.txt") \
        if ip_path.suffix else ip_path.with_name(ip_path.name + ".cidr.txt")

    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    header_lines = [
        f"# VPN/Proxy/Abuse blocklist — generated {ts}",
        f"# Total unique IPs: {len(ips)}  |  Total CIDRs: {len(cidrs)}",
        "# Feeds:",
        *[f"#   {name}: {cnt}" for name, cnt in sorted(per_feed_counts.items())],
        "",
    ]

    sorted_ips = sorted(ips, key=lambda s: tuple(int(p) for p in s.split(".")))
    _atomic_write(ip_path, "\n".join(header_lines + sorted_ips) + "\n")

    _atomic_write(cidr_path,
                  "\n".join(header_lines + sorted(cidrs)) + "\n")

    return ip_path, cidr_path
