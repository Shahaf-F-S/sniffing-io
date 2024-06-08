# test.py

from sniffingio import Sniffer, SniffSettings, write_pcap, pfv

def main() -> None:

    ip_filter = pfv(names=['host'], values=['192.168.0.124', '192.168.0.45'])
    tcp_filter = pfv(names=['port'], values=[6000])

    p_filter = ip_filter & ~tcp_filter

    print(p_filter.format())

    data = SniffSettings(count=10, static_filter=p_filter)

    sniffer = Sniffer(data)
    sniffed = sniffer.start()

    write_pcap(sniffed, "packets.pcap")

if __name__ == "__main__":
    main()
