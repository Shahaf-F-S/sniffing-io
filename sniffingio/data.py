# data.py

from dataclasses import dataclass
from typing import Callable, Iterable

from sniffingio.callbacks import PacketCallback
from sniffingio.filters import LivePacketFilter, PacketFilterOperand

from scapy.all import NetworkInterface, PacketList, Packet

__all__ = [
    "SniffSettings",
    "NetworkInterface",
    "Packet",
    "PacketList"
]

@dataclass(slots=True)
class SniffSettings:

    count: int = 0
    timeout: int = None
    store: bool = True
    quiet: bool = True
    callback: PacketCallback = None
    printer: bool | PacketCallback = None
    live_filter: LivePacketFilter = None
    stop_filter: LivePacketFilter = None
    interface: str | NetworkInterface = None
    static_filter: str | dict | PacketFilterOperand | Iterable[PacketFilterOperand] = None
    start_callback: Callable[[], ...] = None
