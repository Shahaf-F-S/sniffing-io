# listener.py

import socket
from dataclasses import dataclass, field
from typing import Iterable, Generator

from scapy.layers.inet import IP, TCP, Ether
from scapy.packet import Raw, Packet


__all__ = [
    "response_data",
    "response",
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


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Data:

    ack: int
    seq: int
    flags: str
    payload: bytes | None = None

    @classmethod
    def from_packet(cls, packet: Packet) -> Data:
        tcp = tcp_layer(packet)

        return cls(
            ack=tcp.ack,
            seq=tcp.seq,
            flags=tcp.flags,
            payload=packet[Raw].load if Raw in Packet else None
        )

    def response(self, payload: bytes = None) -> Data:
        return response_data(self, payload=payload)


def response_data(data: Packet | Data, payload: bytes = None) -> Data:
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


def response(packet: Packet, payload: bytes = None) -> Packet:
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


type PartialSignature = Iterable[
    tuple[
        str | set[str] | None,
        str | set[str] | None,
        int | set[int] | tuple[int, int] | None
    ]
]


def default_signature(signature: PartialSignature) -> PartialSignature:
    mac, ip, port = signature

    if isinstance(mac, str):
        mac = {mac}

    if isinstance(ip, str):
        ip = {ip}

    if isinstance(port, int):
        port = {port}

    return mac, ip, port


def match_flags(flags: str, signature: str | set[str] | None) -> bool:
    if signature is None:
        return True

    if isinstance(signature, str):
        return flags == signature

    return flags in signature


def match_address(address: str, signature: str | set[str] | None) -> bool:
    if signature is None:
        return True

    if isinstance(signature, str):
        return address == signature

    return address in signature


def match_port(port: int, signature: int | set[int] | tuple[int, int] | None) -> bool:
    if signature is None:
        return True

    if isinstance(signature, int):
        return port == signature

    if isinstance(signature, set):
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

    @classmethod
    def load(cls, mac: str, ip: str, port: int) -> Peer:
        return cls((mac, ip, port))

    def match_mac(self, signature: str | set[str] | None) -> bool:
        return match_address(self.mac, signature)

    def match_ip(self, signature: str | set[str] | None) -> bool:
        return match_address(self.ip, signature)

    def match_port(self, signature: int | set[int] | tuple[int, int] | None) -> bool:
        return match_port(self.port, signature)

    def match(self, signature: PartialSignature) -> bool:
        if not signature:
            return True

        return all(
            self.match_mac(s[0]) and self.match_ip(s[1]) and self.match_port(s[2])
            for s in signature
        )


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Channel:

    source: Peer
    destination: Peer

    @classmethod
    def signature(cls, packet: Packet) -> Channel:
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

    def flip(self) -> Channel:
        return Channel(destination=self.source, source=self.destination)


def filter_channels(
    channels: Iterable[Channel],
    source: PartialSignature | None = None,
    destination: PartialSignature | None = None
) -> Iterable[Channel]:
    source = default_signature(source)
    destination = default_signature(destination)

    return filter(
        lambda channel: channel.match(source=source, destination=destination),
        channels
    )

@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Communication:

    channel: Channel
    data: Data

    @classmethod
    def signature(cls, packet: Packet) -> Communication:
        return cls(
            channel=Channel.signature(packet),
            data=Data.from_packet(packet)
        )

    def channel_flip(self) -> Channel:
        return self.channel.flip()

    def response_data(self, payload: bytes = None) -> Data:
        return self.data.response(payload=payload)

    def response_communication(self, payload: bytes = None) -> Communication:
        return Communication(
            channel=self.channel_flip(),
            data=self.response_data(payload=payload)
        )

    def match(
        self,
        source: PartialSignature | None = None,
        destination: PartialSignature | None = None,
        flags: str | set[str] | None = None
    ) -> bool:
        return (
            match_flags(self.data.flags, signature=flags) and
            self.channel.match(source=source, destination=destination)
        )

def filter_communications(
    communications: Iterable[Communication],
    source: PartialSignature = None,
    destination: PartialSignature = None,
    flags: str | set[str] = None
) -> Iterable[Communication]:
    source = default_signature(source)
    destination = default_signature(destination)

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
        flags: str | set[str] | None = None
    ) -> None:
        if (source, destination, flags) != (None, None, None):
            signature = Communication.signature(packet)

            if not signature.match(source=source, destination=destination, flags=flags):
                return

        self.packet = packet

    @property
    def current_packet(self) -> Packet:
        if self.packet is None:
            raise ValueError('no packet was collected')

        return self.packet

    def current_signature(self) -> Communication:
        return Communication.signature(self.current_packet)

    def response_packet(self, payload: bytes = None) -> Packet:
        return response(self.current_packet, payload=payload)

    def response_signature(self, payload: bytes = None) -> Communication:
        return self.current_signature().response_communication(payload=payload)

    def response_state(self, payload: bytes = None) -> State:
        return State(self.response_packet(payload=payload))

    def copy(self) -> State:
        return State(self.current_packet)


@dataclass
class Hub:

    channels: dict[Channel, State] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.channels)

    def __getitem__(self, key: Channel | Packet) -> State:
        return self.get(key)

    def copy(self) -> Hub:
        return Hub({key: value.copy() for key, value in self.channels.items()})

    def update(self, hub: Hub) -> None:
        self.channels.update(hub.channels)

    def collect(
        self,
        packet: Packet,
        source: PartialSignature = None,
        destination: PartialSignature = None,
        flags: str | set[str] = None
    ) -> None:
        if not isinstance(packet, Packet):
            raise ValueError(f'expected type {Packet}, got: {packet}')

        signature = Channel.signature(packet)

        if not (
            signature.match(source=source, destination=destination) and
            match_flags(tcp_layer(packet).flags, signature=flags)
        ):
            return

        self.channels.setdefault(signature, State()).collect(packet)

    def get(self, key: Channel | Packet) -> State:
        if not isinstance(key, (Packet, Channel)):
            raise ValueError(f'key must be of type {Channel} or {Packet}, got: {key}')

        if isinstance(key, Packet):
            key = Channel.signature(key)

        return self.channels[key]

    def filter(
        self,
        source: PartialSignature = None,
        destination: PartialSignature = None,
        flags: str | set[str] = None
    ) -> Generator[Channel, None, None]:
        if flags is None:
            yield from filter_channels(
                self.channels.keys(),
                source=source, destination=destination
            )

        for key, value in self.channels.items():
            if (
                key.match(source=source, destination=destination) and
                (
                    (value.packet is None) or
                    match_flags(tcp_layer(value.packet).flags, signature=flags)
                )
            ):
                yield key
