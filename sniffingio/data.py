# data.py

from io import BytesIO
from dataclasses import dataclass
from typing import Callable

from sniffingio.callbacks import PacketCallback
from sniffingio.filters import LivePacketFilter, BaseFilter

from scapy.all import NetworkInterface, PacketList, Packet, rdpcap

__all__ = [
    "dump_packet",
    "load_packet",
    "SniffSettings",
    "NetworkInterface",
    "Packet",
    "PacketList",
    "settings"
]

@dataclass(slots=True)
class SniffSettings:

    count: int = 0
    timeout: int = None
    store: bool = True
    quiet: bool = True
    on_packet: PacketCallback = None
    printer: bool | PacketCallback = None
    dynamic_filter: LivePacketFilter = None
    shutdown_filter: LivePacketFilter = None
    interface: str | NetworkInterface = None
    static_filter: str | BaseFilter = None
    on_start: Callable[[], ...] = None

settings = SniffSettings


def dump_packet(packet: Packet | PacketList) -> bytes:
    return bytes(packet)


def load_packet(data: bytes) -> PacketList:
    return rdpcap(BytesIO(data))
