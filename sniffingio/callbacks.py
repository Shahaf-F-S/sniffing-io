# callbacks.py

from dataclasses import dataclass
from typing import Callable

from scapy.all import Packet


__all__ = [
    "PacketCallback"
]


@dataclass
class PacketCallback:

    callback: Callable[[Packet], ...]
    disabled: bool = False

    def __call__(self, *args, **kwargs):
        return self.execute(*args, **kwargs)

    def disable(self) -> None:
        self.disabled = True

    def enable(self) -> None:
        self.disabled = False

    def execute(self, packet: Packet):
        if self.disabled:
            return

        self.callback(packet)
