# Sniffing IO

> A simple package for packet sniffing, with static/dynamic filtering options, real-time reaction, I/O operations and more.

> The sniffing mechanism of sniffing-io is primarily based on the Scapy sniff function, but extends functionality and ease of control.

Installation
-----------
````
pip install sniffing-io
````

example
-----------

````python
from sniffingio import PacketFilter, Sniffer, SniffSettings, write_pcap

protocol_filter = PacketFilter(protocols=["tcp", "udp"])
source_host_filter = PacketFilter(source_hosts=["192.168.0.37"])
destination_host_filter = PacketFilter(destination_hosts=["192.168.0.37"])
port_filter = PacketFilter(source_ports=[6000])

static_filter = (
    protocol_filter &
    (source_host_filter | destination_host_filter) &
    ~port_filter
)
print(static_filter.format())

data = SniffSettings(count=10, static_filter=static_filter)

sniffer = Sniffer(data)
sniffed = sniffer.start()

write_pcap(sniffed, "packets.pcap")
````
