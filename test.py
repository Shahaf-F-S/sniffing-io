# test.py

from sniffingio import PacketFilter, Sniffer, SniffSettings, write_pcap

def main() -> None:
    """A function to run the main test."""

    protocol_filter = PacketFilter(protocols=["tcp", "udp"])
    source_host_filter = PacketFilter(source_hosts=["192.168.0.37"])
    destination_host_filter = PacketFilter(destination_hosts=["192.168.0.37"])

    static_filter = protocol_filter & (source_host_filter | destination_host_filter)
    print(static_filter.format())

    data = SniffSettings(count=10, static_filter=static_filter)

    sniffer = Sniffer(data)
    sniffed = sniffer.start()

    write_pcap(sniffed, "packets.pcap")

if __name__ == "__main__":
    main()
