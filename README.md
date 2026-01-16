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
from sniffingio import pfv, Sniffer, SniffSettings, write_pcap

ip_filter = pfv(names=['host'], values=['192.168.0.124', '192.168.0.45'])
tcp_filter = pfv(names=['port'], values=[6000])

static_filter = ip_filter & ~tcp_filter

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
from sniffingio import Intersection, pfv

pf1 = pfv(names=['host'], values=['192.168.0.124', '192.168.0.45'])
pf2 = pfv(names=['port'], values=[6000])

intersection1 = Intersection((pf1, pf2))
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
from sniffingio import Union, pfv

pf1 = pfv(names=['host'], values=['192.168.0.124', '192.168.0.45'])
pf2 = pfv(names=['port'], values=[6000])

union1 = Union((pf1, pf2))
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
from sniffingio import Negation, pfv

pf = pfv(values=["tcp", "udp"])

negation1 = Negation(pf)
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
from sniffingio import pfv, load_filters

ip_filter = pfv(names=['host'], values=['192.168.0.124', '192.168.0.45'])
tcp_filter = pfv(names=['port'], values=[6000])

org_pf = ip_filter & ~tcp_filter

org_pf_dump = org_pf.dump()
loaded_pf = load_filters(org_pf_dump)

print(org_pf_dump)
print(loaded_pf.format())
print('equal objects:', org_pf == loaded_pf)
````

output:
```
{'filters': ({'types': None, 'names': ['host'], 'values': ['192.168.0.124', '192.168.0.45'], 'source_values': None, 'destination_values': None, 'attributes': None, 'type': 'values'}, {'filter': {'types': None, 'names': ['port'], 'values': [6000], 'source_values': None, 'destination_values': None, 'attributes': None, 'type': 'values'}, 'type': 'negation'}), 'type': 'intersection'}
(((host 192.168.0.124) or (host 192.168.0.45)) and (not (port 6000)))
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
static_filter: str | BasePacketFilter = None
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
