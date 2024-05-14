# test.py

from sniffingio import Sniffer, SniffSettings, write_pcap, PacketFilterValues

def main() -> None:
    """A function to run the main test."""

    ip_filter = PacketFilterValues(
        names=['host'], values=['192.168.0.124', '192.168.0.45']
    )
    tcp_filter = PacketFilterValues(
        names=['port'], values=[6000]
    )

    static_filter = ip_filter & ~tcp_filter
    print(static_filter.format())

    data = SniffSettings(count=10, static_filter=static_filter)

    sniffer = Sniffer(data)
    sniffed = sniffer.start()

    write_pcap(sniffed, "packets.pcap")

if __name__ == "__main__":
    main()
