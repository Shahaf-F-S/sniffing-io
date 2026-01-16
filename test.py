# test.py

from sniffingio import Sniffer, SniffSettings, write_pcap, ip_filter, port_filter


def main() -> None:

    ips = ip_filter({'192.168.0.1', '192.168.0.45'})
    ports = port_filter({6000})

    p_filter = ips & ~ports

    print(p_filter.format())

    data = SniffSettings(count=10, static_filter=p_filter)

    sniffer = Sniffer(data)
    sniffed = sniffer.start()

    write_pcap(sniffed, "packets.pcap")


if __name__ == "__main__":
    main()
