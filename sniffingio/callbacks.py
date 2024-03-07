# callbacks.py

from io import BytesIO
from dataclasses import dataclass
from typing import Callable

from scapy.all import Packet, PacketList, wrpcap, rdpcap

__all__ = [
    "dump_packet",
    "load_packet",
    "PacketCallback"
]

def dump_packet(packet: Packet | PacketList) -> bytes:

    data = BytesIO()

    payload = []

    data.write = payload.append

    wrpcap(data, packet)

    return b"".join(payload)

def load_packet(data: bytes) -> PacketList:

    return rdpcap(BytesIO(data))

@dataclass(slots=True)
class PacketCallback:

    callback: Callable[[Packet], ...]

    disabled: bool = False
    result: bool = False

    def __call__(self, *args, **kwargs) -> ...:

        return self.execute(*args, **kwargs)

    def disable(self) -> None:

        self.disabled = True

    def enable(self) -> None:

        self.disabled = False

    def execute(self, packet: Packet) -> ...:

        if self.disabled:
            return

        result = self.callback(packet)

        if not self.result:
            return

        return result
