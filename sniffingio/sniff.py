# sniff.py

from io import BytesIO
import threading

from scapy.all import (
    PacketList, wrpcap, Packet, cast, rdpcap,
    AsyncSniffer as ScapyAsyncSniffer
)

from sniffingio.data import SniffSettings
from sniffingio.filters import format_packet_filters, load_packet_filter

__all__ = [
    "sniff",
    "Sniffer",
    "write_pcap",
    "read_pcap"
]

class Sniffer:

    def __init__(self, data: SniffSettings = None) -> None:

        if data is None:
            data = SniffSettings()

        self.data = data

        self._sniffer = ScapyAsyncSniffer()

    def packets(self) -> PacketList:

        return cast(PacketList, self._sniffer.results)

    def start(self, data: SniffSettings = None) -> PacketList:

        data = data or self.data or SniffSettings()

        callback = None

        if data.callback and data.printer:
            callback = lambda p: (data.callback(p), data.printer(p))

        elif data.callback:
            callback = data.callback

        elif data.printer:
            if data.printer is True:
                callback = print

            else:
                callback = data.printer

        static_filter = None

        if data.static_filter is not None:
            static_filter = data.static_filter

            if isinstance(static_filter, dict):
                static_filter = load_packet_filter(static_filter)

            if not isinstance(static_filter, str):
                static_filter = format_packet_filters(static_filter)

        # noinspection PyProtectedMember
        self._sniffer._run(
            count=data.count,
            store=data.store,
            quiet=data.quiet,
            timeout=data.timeout,
            iface=data.interface,
            prn=callback,
            lfilter=data.live_filter,
            filter=static_filter,
            stop_filter=data.stop_filter,
            started_callback=data.start_callback
        )

        return self.packets()

    def thread_start(self) -> None:

        threading.Thread(target=self.start).start()

    def stop(self) -> None:

        self._sniffer.stop()

def sniff(data: SniffSettings) -> PacketList:

    return Sniffer(data).start()

def write_pcap(packet: PacketList | list[Packet] | Packet, io: BytesIO | str) -> None:

    wrpcap(io, packet)

def read_pcap(io: BytesIO | str) -> PacketList | list[Packet] | Packet:

    return rdpcap(io)
