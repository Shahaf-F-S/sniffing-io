# listener.py

import socket
from dataclasses import dataclass, field
from typing import Iterable, Generator

from scapy.layers.inet import IP, TCP, Ether
from scapy.packet import Raw, Packet


__all__ = [
    "response_data",
    "response_packet",
    "Peer",
    "TCPCommunication",
    "filter_channels",
    "State",
    "TCPHub",
    "Channel",
    "TCPData",
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
class TCPData:

    ack: int
    seq: int
    flags: str
    payload: bytes | None = None

    @classmethod
    def from_packet(cls, packet: Packet) -> TCPData:
        tcp = tcp_layer(packet)

        return cls(
            ack=tcp.ack,
            seq=tcp.seq,
            flags=str(tcp.flags),
            payload=packet[Raw].load if str(tcp.flags) == 'PA' else None
        )

    def response(self, flags: str = None, payload: bytes = None) -> TCPData:
        return response_data(self, flags=flags, payload=payload)

    def next(self, flags: str = None, payload: bytes = None) -> TCPData:
        return next_data(self, flags=flags, payload=payload)

    def to_tcp(self, source: int, destination: int) -> TCP | Packet:
        tcp = TCP(sport=source, dport=destination, ack=self.ack, seq=self.seq, flags=self.flags)

        if self.payload:
            tcp = tcp / self.payload

        return tcp


def response_data(data: Packet | TCPData, flags: str = None, payload: bytes = None) -> TCPData:
    if flags is None and payload:
        flags = 'PA'

    elif flags is None:
        flags = 'A'

    if not isinstance(data, TCPData):
        data = TCPData.from_packet(data)

    return TCPData(
        ack=data.seq + len(data.payload or b''),
        seq=data.ack,
        flags=flags,
        payload=payload
    )


def next_data(data: Packet | TCPData, flags: str = None, payload: bytes = None) -> TCPData:
    if flags is None and payload:
        flags = 'PA'

    elif flags is None:
        flags = 'A'

    if not isinstance(data, TCPData):
        data = TCPData.from_packet(data)

    return TCPData(
        seq=data.seq + len(data.payload or b''),
        ack=data.ack,
        flags=flags,
        payload=payload
    )


def response_packet(packet: Packet, flags: str = None, payload: bytes = None) -> Packet:
    ether = ether_layer(packet)
    ip = ip_layer(packet)
    tcp = tcp_layer(packet)

    new_ether = Ether(src=ether.dst, dst=ether.src)
    new_ip = IP(src=ip.dst, dst=ip.src)
    new_tcp = response_data(packet, flags=flags, payload=payload).to_tcp(
        source=tcp.dport, destination=tcp.sport
    )

    return new_ether / new_ip / new_tcp


def next_packet(packet: Packet, flags: str = None, payload: bytes = None) -> Packet:
    ether = ether_layer(packet)
    ip = ip_layer(packet)
    tcp = tcp_layer(packet)

    new_ether = Ether(src=ether.dst, dst=ether.src)
    new_ip = IP(src=ip.dst, dst=ip.src)
    new_tcp = next_data(packet, flags=flags, payload=payload).to_tcp(
        source=tcp.dport, destination=tcp.sport
    )

    return new_ether / new_ip / new_tcp


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

    def to_packet(self) -> Packet:
        return (
            Ether(src=self.source.mac, dst=self.destination.mac) /
            IP(src=self.source.ip, dst=self.destination.ip)
        )


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
class TCPCommunication:

    channel: Channel
    data: TCPData

    @classmethod
    def from_packet(cls, packet: Packet) -> TCPCommunication:
        return cls(
            channel=Channel.signature(packet),
            data=TCPData.from_packet(packet)
        )

    def to_tcp(self) -> TCP | Packet:
        return self.data.to_tcp(
            source=self.channel.source.port,
            destination=self.channel.destination.port
        )

    def to_packet(self) -> Packet:
        return self.channel.to_packet() / self.to_tcp()

    def channel_flip(self) -> Channel:
        return self.channel.flip()

    def response_data(self, flags: str = None, payload: bytes = None) -> TCPData:
        return self.data.response(flags=flags, payload=payload)

    def next_data(self, flags: str = None, payload: bytes = None) -> TCPData:
        return self.data.next(flags=flags, payload=payload)

    def response(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return TCPCommunication(
            channel=self.channel_flip(),
            data=self.response_data(flags=flags, payload=payload)
        )

    def next(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return TCPCommunication(
            channel=self.channel,
            data=self.next_data(flags=flags, payload=payload)
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
    communications: Iterable[TCPCommunication],
    source: PartialSignature = None,
    destination: PartialSignature = None,
    flags: str | set[str] = None
) -> Iterable[TCPCommunication]:
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
    ) -> bool:
        if (source, destination, flags) != (None, None, None):
            signature = TCPCommunication.from_packet(packet)

            if not signature.match(source=source, destination=destination, flags=flags):
                return False

        self.packet = packet

        return True

    @property
    def current_packet(self) -> Packet:
        if self.packet is None:
            raise ValueError('no packet was collected')

        return self.packet

    def current_communication(self) -> TCPCommunication:
        return TCPCommunication.from_packet(self.current_packet)

    def response_packet(self, flags: str = None, payload: bytes = None) -> Packet:
        return response_packet(self.current_packet, flags=flags, payload=payload)

    def next_packet(self, flags: str = None, payload: bytes = None) -> Packet:
        return next_packet(self.current_packet, flags=flags, payload=payload)

    def response_communication(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return self.current_communication().response(flags=flags, payload=payload)

    def next_communication(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return self.current_communication().next(flags=flags, payload=payload)

    def response(self, flags: str = None, payload: bytes = None) -> State:
        return State(self.response_packet(flags=flags, payload=payload))

    def next(self, flags: str = None, payload: bytes = None) -> State:
        return State(self.next_packet(flags=flags, payload=payload))

    def copy(self) -> State:
        return State(self.current_packet)


@dataclass
class TCPHub:

    channels: dict[Channel, State] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.channels)

    def __getitem__(self, key: Channel | Packet) -> State:
        return self.get(key)

    def copy(self) -> TCPHub:
        return TCPHub({key: value.copy() for key, value in self.channels.items()})

    def update(self, hub: TCPHub) -> None:
        self.channels.update(hub.channels)

    def collect(
        self,
        packet: Packet,
        source: PartialSignature = None,
        destination: PartialSignature = None,
        flags: str | set[str] = None
    ) -> bool:
        if not isinstance(packet, Packet):
            raise ValueError(f'expected type {Packet}, got: {packet}')

        signature = Channel.signature(packet)

        if not (
            signature.match(source=source, destination=destination) and
            match_flags(tcp_layer(packet).flags, signature=flags)
        ):
            return False

        self.channels.setdefault(signature, State()).collect(packet)

        return True

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
