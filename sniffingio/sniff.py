# sniff.py

import threading

from scapy.all import PacketList, AsyncSniffer as ScapyAsyncSniffer

from sniffingio.data import SniffSettings
from sniffingio.filters import BaseFilter


__all__ = [
    "sniff",
    "Sniffer"
]


class Sniffer:

    def __init__(self, settings: SniffSettings = None) -> None:
        if settings is None:
            settings = SniffSettings()

        self.settings = settings
        self._sniffer = ScapyAsyncSniffer()

    def packets(self) -> PacketList:
        return self._sniffer.results

    def start(self, data: SniffSettings = None) -> PacketList:
        data = data or self.settings or SniffSettings()

        callback = None

        if data.on_packet and data.printer:
            callback = lambda p: (data.on_packet(p), data.printer(p))

        elif data.on_packet:
            callback = data.on_packet

        elif data.printer:
            if data.printer is True:
                callback = print

            else:
                callback = data.printer

        static_filter = data.static_filter

        if isinstance(static_filter, BaseFilter):
            static_filter = static_filter.format()

        # noinspection PyProtectedMember
        self._sniffer._run(
            count=data.count,
            store=data.store,
            quiet=data.quiet,
            timeout=data.timeout,
            iface=data.interface,
            prn=callback,
            lfilter=data.dynamic_filter,
            filter=static_filter,
            stop_filter=data.shutdown_filter,
            started_callback=data.on_start
        )

        return self.packets()

    def start_thread(self) -> None:
        threading.Thread(target=self.start).start()

    def stop(self) -> None:
        self._sniffer.stop()

def sniff(data: SniffSettings) -> PacketList:
    return Sniffer(data).start()
