import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Config:
    token: str = os.getenv("DISCORD_TOKEN", "").strip()
    channel_id: int = int(os.getenv("DISCORD_CHANNEL_ID", "0") or 0)
    refresh_minutes: int = max(30, int(os.getenv("REFRESH_MINUTES", "90") or 90))
    blocklist_path: str = os.getenv("BLOCKLIST_PATH", "blocklist.txt").strip()
    disabled_feeds: frozenset = field(
        default_factory=lambda: frozenset(
            f.strip().lower()
            for f in os.getenv("DISABLED_FEEDS", "").split(",")
            if f.strip()
        )
    )

    def validate(self) -> None:
        if not self.token:
            raise RuntimeError("DISCORD_TOKEN is not set")
        if not self.channel_id:
            raise RuntimeError("DISCORD_CHANNEL_ID is not set")


CONFIG = Config()
