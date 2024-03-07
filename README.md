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

Sniffer interface:
````python
from sniffingio import Sniffer, SniffSettings, PacketList

sniffer = Sniffer(SniffSettings(...))

sniffed1: PacketList = sniffer.start()

sniffer.thread_start()
sniffer.stop()

sniffed2: PacketList = sniffer.packets()
````

PacketFilter interface:

intersection:
````python
from sniffingio import PacketFilterIntersection, PacketFilter

pf1 = PacketFilter(protocols=["tcp", "udp"])
pf2 = PacketFilter(source_ports=[6000])

intersection1 = PacketFilterIntersection((pf1, pf2))
intersection2 = pf1 & pf2

print("same operation:", intersection1 == intersection2)
print("BPF:", intersection2.format())
````

output:
```
same operation: True
BPF: (((tcp or udp)) and ((src port 6000)))
```

union:
````python
from sniffingio import PacketFilterUnion, PacketFilter

pf1 = PacketFilter(protocols=["tcp", "udp"])
pf2 = PacketFilter(source_ports=[6000])

union1 = PacketFilterUnion((pf1, pf2))
union2 = pf1 | pf2

print("same operation:", union1 == union2)
print("BPF:", union2.format())
````

output:
```
same operation: True
BPF: (((tcp or udp)) or ((src port 6000)))
```

negation:
````python
from sniffingio import PacketFilterNegation, PacketFilter

pf = PacketFilter(protocols=["tcp", "udp"])

negation1 = PacketFilterNegation(pf)
negation2 = ~pf

print("same operation:", negation1 == negation2)
print("BPF:", negation2.format())
````

output:
```
same operation: True
BPF: (not ((tcp or udp)))
```

simple PacketFilter I/O:
````python
from sniffingio import PacketFilter, load_packet_filter, dump_packet_filter

protocol_filter = PacketFilter(protocols=["tcp", "udp"])
source_host_filter = PacketFilter(source_hosts=["192.168.0.37"])
destination_host_filter = PacketFilter(destination_hosts=["192.168.0.37"])
port_filter = PacketFilter(source_ports=[6000])

org_pf = (
    protocol_filter &
    (source_host_filter | destination_host_filter) &
    ~port_filter
)

org_pf_dump = dump_packet_filter(org_pf)
loaded_pf = load_packet_filter(org_pf_dump)

print(org_pf_dump)
print(loaded_pf.format())
print('equal objects:', org_pf == loaded_pf)
````

output:
```
{'__type__': 'PacketFilterIntersection', 'filters': [{'__type__': 'PacketFilterIntersection', 'filters': [{'protocols': ['tcp', 'udp'], 'destination_hosts': None, 'source_ports': None, 'destination_ports': None, 'source_hosts': None, '__type__': 'PacketFilter'}, {'__type__': 'PacketFilterUnion', 'filters': [{'protocols': None, 'destination_hosts': None, 'source_ports': None, 'destination_ports': None, 'source_hosts': ['192.168.0.37'], '__type__': 'PacketFilter'}, {'protocols': None, 'destination_hosts': ['192.168.0.37'], 'source_ports': None, 'destination_ports': None, 'source_hosts': None, '__type__': 'PacketFilter'}]}]}, {'__type__': 'PacketFilterNegation', 'filter': {'protocols': None, 'destination_hosts': None, 'source_ports': [6000], 'destination_ports': None, 'source_hosts': None, '__type__': 'PacketFilter'}}]}
((((tcp or udp)) and (((src host 192.168.0.37)) or ((dst host 192.168.0.37)))) and (not ((src port 6000))))
equal objects: True
```

SniffSettings options:

````python
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
````

PacketFilter options:
````python
protocols: list[str] = None
source_hosts: list[str] = None
source_ports: list[int] = None
destination_hosts: list[str] = None
destination_ports: list[int] = None
````

Scapy Packet/PacketList I/O operations:
````python
from sniffingio import PacketList, load_packet, dump_packet, write_pcap, read_pcap

org_p: PacketList = ...

org_p_dump: bytes = dump_packet(org_p)
loaded_p: PacketList = load_packet(org_p_dump)

print("equal data:", org_p_dump == dump_packet(loaded_p))

write_pcap(org_p, "packets.pcap")
read_p = read_pcap("packets.pcap")

print("equal data:", org_p_dump == dump_packet(read_p))
````

output:
```
equal data: True
equal data: True
```
