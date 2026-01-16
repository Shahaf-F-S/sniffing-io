# listener.py

import socket
from dataclasses import dataclass, field
from typing import Iterable, Generator

from scapy.layers.inet import IP, TCP, Ether
from scapy.packet import Raw, Packet


__all__ = [
    "spoof_response_data",
    "spoof_response",
    "Peer",
    "Communication",
    "filter_channels",
    "State",
    "Hub",
    "Channel",
    "Data",
    "filter_communications"
]


def ether_layer(packet: Packet) -> Ether:
    if not packet.haslayer(Ether):
        raise ValueError('packet must contain an Ether layer.')

    return packet[Ether]


def ip_layer(packet: Packet) -> IP:
    if not packet.haslayer(IP):
        raise ValueError('packet must contain an IP layer.')

    return packet[IP]


def tcp_layer(packet: Packet) -> TCP:
    if not packet.haslayer(TCP):
        raise ValueError('packet must contain a TCP layer.')

    return packet[TCP]


def raw_layer(packet: Packet) -> Raw:
    if not packet.haslayer(Raw):
        raise ValueError('packet must contain a Raw layer.')

    return packet[Raw]


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Data:

    ack: int
    seq: int
    flags: str
    payload: bytes | None = None

    @classmethod
    def from_packet(cls, packet: Packet) -> "Data":
        tcp = tcp_layer(packet)

        return cls(
            ack=tcp.ack,
            seq=tcp.seq,
            flags=tcp.flags,
            payload=packet[Raw].load if Raw in Packet else None
        )

    def next(self, payload: bytes = None) -> "Data":
        return spoof_response_data(self, payload=payload)

    def copy(self) -> "Data":
        return Data(
            ack=self.ack, seq=self.seq,
            flags=self.flags, payload=self.payload
        )


def spoof_response_data(
        data: Packet | Data, payload: bytes = None
) -> Data:
    if not isinstance(data, Data):
        data = Data.from_packet(data)

    if data.flags not in ('PA', 'A'):
        raise ValueError(f"input TCP flags must be either 'PA' or 'A', not: '{data.flags}'")

    if (data.flags == 'PA') and (data.payload is None):
        raise ValueError(f"input must contain nonempty payload when TCP flags is: 'PA'")

    elif payload is not None:
        raise ValueError(f"cannot add payload to 'A' TCP packet.")

    return Data(
        ack=data.seq + (0 if data.flags == 'A' else len(payload or '')),
        seq=data.ack,
        flags='PA' if data.flags == 'A' else 'A',
        payload=payload
    )


def spoof_response(packet: Packet, payload: bytes = None) -> Packet:
    ether = ether_layer(packet)
    ip = ip_layer(packet)
    tcp = tcp_layer(packet)

    ack = tcp.seq
    seq = tcp.ack

    if tcp.flags == 'PA':
        if Raw not in packet:
            raise ValueError('packet must contain a Raw layer.')

        raw: Raw = packet[Raw]

        seq += len(raw.load)

        flags = 'A'

    elif tcp.flags == 'A':
        flags = 'PA'

    else:
        raise ValueError(f"cannot infer flags for new TCP packet from: '{tcp.flags}'")

    new_ether = Ether(src=ether.dst, dst=ether.src)
    new_ip = IP(src=ip.dst, dst=ip.src)
    new_tcp = TCP(sport=tcp.dport, dport=tcp.sport, ack=ack, seq=seq, flags=flags)

    new_packet = new_ether / new_ip / new_tcp

    if payload is not None:
        if flags != 'PA':
            raise ValueError(f"cannot add payload to a TCP packet with flag: '{flags}'")

        new_packet = new_packet / packet

    return new_packet


type PartialSignature = tuple[
    str | list[str] | None,
    str | list[str] | None,
    int | list[int] | tuple[int, int] | None
]


def natural_signature(signature: PartialSignature) -> PartialSignature:
    mac, ip, port = signature

    if isinstance(mac, str):
        mac = [mac]

    if isinstance(ip, str):
        ip = [ip]

    if isinstance(port, int):
        port = [port]

    return mac, ip, port


def match_flags(flags: str, signature: str | list[str] | None) -> bool:
    if signature is None:
        return True

    if isinstance(signature, str):
        signature = [signature]

    return flags in signature


def match_address(address: str, signature: str | list[str] | None) -> bool:
    if signature is None:
        return True

    if isinstance(signature, str):
        signature = [signature]

    return address in signature


def match_port(port: int, signature: int | list[int] | tuple[int, int] | None) -> bool:
    if signature is None:
        return True

    if isinstance(signature, int):
        signature = [signature]

    if isinstance(signature, list):
        return port in signature

    return signature[0] <= port >= signature[1]


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Peer:

    signature: tuple[str, str, int]

    @property
    def host(self) -> str:
        return socket.gethostbyaddr(self.ip)[0]

    @property
    def mac(self) -> str:
        return self.signature[0]

    @property
    def ip(self) -> str:
        return self.signature[1]

    @property
    def port(self) -> int:
        return self.signature[2]

    def match_mac(self, signature: str | list[str] | None) -> bool:
        return match_address(self.mac, signature)

    def match_ip(self, signature: str | list[str] | None) -> bool:
        return match_address(self.ip, signature)

    def match_port(self, signature: int | list[int] | tuple[int, int] | None) -> bool:
        return match_port(self.port, signature)

    def match(self, signature: PartialSignature) -> bool:
        if signature is None:
            return True

        return (
            self.match_mac(signature[0]) and
            self.match_ip(signature[1]) and
            self.match_port(signature[2])
        )

    def copy(self) -> "Peer":
        return Peer((self.mac, self.ip, self.port))

@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Channel:

    source: Peer
    destination: Peer

    @classmethod
    def signature(cls, packet: Packet) -> "Channel":
        ether = ether_layer(packet)
        ip = ip_layer(packet)
        tcp = tcp_layer(packet)

        return cls(
            source=Peer((ether.src, ip.src, tcp.sport)),
            destination=Peer((ether.dst, ip.dst, tcp.dport))
        )

    def match(
        self,
        source: PartialSignature | None = None,
        destination: PartialSignature | None = None
    ) -> bool:
        return self.source.match(source) and self.destination.match(destination)

    def next(self) -> "Channel":
        return Channel(
            destination=self.source.copy(), source=self.destination.copy()
        )

    def copy(self) -> "Channel":
        return Channel(
            source=self.source.copy(), destination=self.destination.copy()
        )

def filter_channels(
    channels: Iterable[Channel],
    source: PartialSignature | None = None,
    destination: PartialSignature | None = None
) -> Iterable[Channel]:
    source = natural_signature(source)
    destination = natural_signature(destination)

    return filter(
        lambda channel: channel.match(source=source, destination=destination),
        channels
    )

@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Communication:

    channel: Channel
    data: Data

    @classmethod
    def signature(cls, packet: Packet) -> "Communication":
        return cls(
            channel=Channel.signature(packet),
            data=Data.from_packet(packet)
        )

    def next_channel(self) -> Channel:
        return self.channel.next()

    def next_data(self, payload: bytes = None) -> Data:
        return self.data.next(payload=payload)

    def next(self, payload: bytes = None) -> "Communication":
        return Communication(
            channel=self.next_channel(), data=self.next_data(payload=payload)
        )

    def copy(self) -> "Communication":
        return Communication(
            channel=self.channel.copy(), data=self.data.copy()
        )

    def match(
        self,
        source: PartialSignature | None = None,
        destination: PartialSignature | None = None,
        flags: str | list[str] | None = None
    ) -> bool:
        return (
            match_flags(self.data.flags, signature=flags) and
            self.channel.match(source=source, destination=destination)
        )

def filter_communications(
    communications: Iterable[Communication],
    source: PartialSignature = None,
    destination: PartialSignature = None,
    flags: str | list[str] = None
) -> Iterable[Communication]:
    source = natural_signature(source)
    destination = natural_signature(destination)

    if isinstance(flags, str):
        flags = [flags]

    for communication in communications:
        if communication.match(source=source, destination=destination, flags=flags):
            yield communication

@dataclass
class State:

    packet: Packet = None

    def collect(
        self,
        packet: Packet,
        source: PartialSignature | None = None,
        destination: PartialSignature | None = None,
        flags: str | list[str] | None = None
    ) -> None:
        if (source, destination, flags) != (None, None, None):
            signature = Communication.signature(packet)

            if not signature.match(source=source, destination=destination, flags=flags):
                return

        self.packet = packet

    def current_packet(self) -> Packet:
        if self.packet is None:
            raise ValueError('no packet was collected')

        return self.packet

    def current_signature(self) -> Communication:
        return Communication.signature(self.current_packet())

    def next_packet(self, payload: bytes = None) -> Packet:
        return spoof_response(self.current_packet(), payload=payload)

    def next_signature(self, payload: bytes = None) -> Communication:
        return self.current_signature().next(payload=payload)

    def next(self, payload: bytes = None) -> "State":
        return State(self.next_packet(payload=payload))

    def copy(self) -> "State":
        return State(self.current_packet())


@dataclass
class Hub:

    channels: dict[Channel, State] = field(default_factory=dict)

    def __iter__(self) -> Iterable[Channel]:
        return self.keys()

    def __len__(self) -> int:
        return len(self.channels)

    def __getitem__(self, key: Channel | Packet) -> State:
        return self.get(key)

    def __setitem__(self, key: Channel | Packet, value: State) -> None:
        return self.set(key, value)

    def copy(self) -> "Hub":
        return Hub(
            {key.copy(): value.copy() for key, value in self.items()}
        )

    def keys(self) -> Iterable[Channel]:
        return self.channels.copy().keys()

    def values(self) -> Iterable[State]:
        return self.channels.copy().values()

    def items(self) -> Iterable[tuple[Channel, State]]:
        return self.channels.copy().items()

    def update(self, hub: "Hub") -> None:
        self.channels.update(hub.channels)

    def collect(
        self,
        packet: Packet,
        source: PartialSignature = None,
        destination: PartialSignature = None,
        flags: str | list[str] = None
    ) -> None:
        if not isinstance(packet, Packet):
            raise ValueError(f'expected type {Packet}, got: {packet}')

        signature = Channel.signature(packet)

        if not (
            signature.match(source=source, destination=destination) and
            match_flags(tcp_layer(packet).flags, signature=flags)
        ):
            return

        if signature not in self.channels:
            self.channels[signature] = State()

        self.channels[signature].collect(packet)

    def get(self, key: Channel | Packet) -> State:
        if not isinstance(key, (Packet, Channel)):
            raise ValueError(f'key must be of type {Channel} or {Packet}, got: {key}')

        if isinstance(key, Packet):
            key = Channel.signature(key)

        return self.channels[key]

    def set(self, key: Channel | Packet, value: State) -> None:
        if not isinstance(value, State):
            raise ValueError(f'value must be of type {State}, got: {value}')

        if isinstance(key, Packet):
            value.collect(key)

            key = Channel.signature(key)

        if not isinstance(key, (Packet, Channel)):
            raise ValueError(f'key must be of type {Channel} or {Packet}, got: {key}')

        self.channels[key] = value

    def filter(
            self,
            source: PartialSignature = None,
            destination: PartialSignature = None,
            flags: str | list[str] = None
    ) -> Generator[Channel, None, None]:
        if flags is None:
            yield from filter_channels(self.keys(), source=source, destination=destination)

        for key, value in self.items():
            if (
                key.match(source=source, destination=destination) and
                (
                    (value.packet is None) or
                    match_flags(tcp_layer(value.packet).flags, signature=flags)
                )
            ):
                yield key
