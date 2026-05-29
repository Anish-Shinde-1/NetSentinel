from dataclasses import dataclass, asdict
from typing import Optional
import uuid


@dataclass(slots=True)
class FirewallRule:
    id: str
    name: str

    app: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None

    direction: str = "both"
    action: str = "block"

    protocol: Optional[str] = None
    enabled: bool = True

    @property
    def inbound_firewall_name(self) -> str:
        return f"NetSentinel-{self.id}-IN"

    @property
    def outbound_firewall_name(self) -> str:
        return f"NetSentinel-{self.id}-OUT"

    @classmethod
    def create(cls, name: str):
        return cls(
            id=uuid.uuid4().hex[:8],
            name=name
        )

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            id=data.get("id", uuid.uuid4().hex[:8]),
            name=data.get("name", "Unnamed Rule"),
            app=data.get("app"),
            dst_ip=data.get("dst_ip"),
            port=int(data["port"]) if data.get("port") else None,
            direction=data.get("direction", "both"),
            action=data.get("action", "block"),
            protocol=data.get("protocol"),
            enabled=data.get("enabled", True),
        )