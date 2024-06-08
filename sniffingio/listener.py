# listener.py

import socket
from dataclasses import dataclass, field
from typing import Iterable, Generator

from scapy.layers.inet import IP, TCP, Ether
from scapy.packet import Raw, Packet

__all__ = [
    "spoof_response",
    "DeviceSignature",
    "CommunicationSignature",
    "filter_channels",
    "CommunicationState",
    "CommunicationHub"
]

def spoof_response(packet: Packet, payload: bytes = None) -> Packet:

    if TCP not in packet:
        raise ValueError('packet must contain a TCP layer.')

    ether: Ether = packet[Ether]
    ip: IP = packet[IP]
    tcp: TCP = packet[TCP]

    new_ether = Ether(src=ether.dst, dst=ether.src)
    new_ip = IP(src=ip.dst, dst=ip.src)
    new_tcp = TCP(sport=tcp.dport, dport=tcp.sport, ack=tcp.seq, seq=tcp.ack, flags='PA')

    if tcp.flags == 'PA':
        if Raw not in packet:
            raise ValueError('packet must contain a Raw layer.')

        raw: Raw = packet[Raw]

        new_tcp.ack += len(raw.load)

    new_packet = new_ether / new_ip / new_tcp

    if payload is not None:
        new_packet = new_packet / packet

    return new_packet

type PartialSignature = tuple[str | None, str | None, int | None]

@dataclass(slots=True, frozen=True, unsafe_hash=True)
class DeviceSignature:

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

    def match(self, signature: PartialSignature = None) -> bool:

        if signature is None:
            return True

        return all(
            (partial is None) or (partial == value)
            for value, partial in zip(self.signature, signature)
        )

    def copy(self) -> "DeviceSignature":

        return DeviceSignature((self.mac, self.ip, self.port))

@dataclass(slots=True, frozen=True, unsafe_hash=True)
class ChannelSignature:

    source: DeviceSignature
    destination: DeviceSignature

    @classmethod
    def signature(cls, packet: Packet) -> "ChannelSignature":

        if TCP not in packet:
            raise ValueError('packet must contain a TCP layer.')

        ether: Ether = packet[Ether]
        ip: IP = packet[IP]
        tcp: TCP = packet[TCP]

        return cls(
            source=DeviceSignature((ether.src, ip.src, tcp.sport)),
            destination=DeviceSignature((ether.dst, ip.dst, tcp.dport))
        )

    def match(
            self,
            source: PartialSignature = None,
            destination: PartialSignature = None
    ) -> bool:

        return self.source.match(source) and self.destination.match(destination)

    def copy(self) -> "ChannelSignature":

        return ChannelSignature(
            source=self.source.copy(), destination=self.destination.copy()
        )

def filter_channels(
        channels: Iterable[ChannelSignature],
        source: PartialSignature = None,
        destination: PartialSignature = None
) -> Generator[ChannelSignature, None, None]:

    return filter(
        lambda channel: channel.match(
            source=source, destination=destination
        ),
        channels
    )

@dataclass(slots=True, frozen=True, unsafe_hash=True)
class CommunicationSignature:

    channel: ChannelSignature

    ack: int
    seq: int

    flags: str

    @classmethod
    def signature(cls, packet: Packet) -> "CommunicationSignature":

        if TCP not in packet:
            raise ValueError('packet must contain a TCP layer.')

        tcp: TCP = packet[TCP]

        return cls(
            channel=ChannelSignature.signature(packet),
            ack=tcp.ack,
            seq=tcp.seq,
            flags=tcp.flags
        )

    def copy(self) -> "CommunicationSignature":

        return CommunicationSignature(
            channel=self.channel.copy(), ack=self.ack, seq=self.seq, flags=self.flags
        )

@dataclass(slots=True)
class CommunicationState:

    packet: Packet = None

    def collect(self, packet: Packet) -> None:

        self.packet = packet

    def signature(self) -> CommunicationSignature:

        return CommunicationSignature.signature(self.current())

    def current(self) -> Packet:

        if self.packet is None:
            raise ValueError('no packet was collected')

        return self.packet

    def current_signature(self) -> CommunicationSignature:

        return CommunicationSignature.signature(self.current())

    def next(self) -> Packet:

        return spoof_response(self.current())

    def next_signature(self) -> CommunicationSignature:

        return CommunicationSignature.signature(self.next())

    def copy(self) -> "CommunicationState":

        return CommunicationState(self.current())

@dataclass(slots=True)
class CommunicationHub:

    channels: dict[ChannelSignature, CommunicationState] = field(default_factory=dict)

    def __iter__(self) -> Iterable[ChannelSignature]:

        return self.keys()

    def __len__(self) -> int:

        return len(self.channels)

    def __getitem__(self, key: ChannelSignature | Packet) -> CommunicationState:

        return self.get(key)

    def __setitem__(self, key: ChannelSignature | Packet, value: CommunicationState) -> None:

        return self.set(key, value)

    def copy(self) -> "CommunicationHub":

        return CommunicationHub(
            {key.copy(): value.copy() for key, value in self.items()}
        )

    def keys(self) -> Iterable[ChannelSignature]:

        return self.channels.copy().keys()

    def values(self) -> Iterable[CommunicationState]:

        return self.channels.copy().values()

    def items(self) -> Iterable[tuple[ChannelSignature, CommunicationState]]:

        return self.channels.copy().items()

    def update(self, hub: "CommunicationHub") -> None:

        self.channels.update(hub.channels)

    def collect(self, packet: Packet) -> None:

        if not isinstance(packet, Packet):
            raise ValueError(f'expected type {Packet}, got: {packet}')

        if (signature := ChannelSignature.signature(packet)) not in self.channels:
            self.channels[signature] = CommunicationState()

        self.channels[signature].collect(packet)

    def get(self, key: ChannelSignature | Packet) -> CommunicationState:

        if not isinstance(key, (Packet, ChannelSignature)):
            raise ValueError(f'key must be of type {ChannelSignature} or {Packet}, got: {key}')

        if isinstance(key, Packet):
            key = ChannelSignature.signature(key)

        return self.channels[key]

    def set(self, key: ChannelSignature | Packet, value: CommunicationState) -> None:

        if not isinstance(value, CommunicationState):
            raise ValueError(f'value must be of type {CommunicationState}, got: {value}')

        if isinstance(key, Packet):
            value.collect(key)

            key = ChannelSignature.signature(key)

        if not isinstance(key, (Packet, ChannelSignature)):
            raise ValueError(f'key must be of type {ChannelSignature} or {Packet}, got: {key}')

        self.channels[key] = value

    def filter(
            self,
            source: PartialSignature = None,
            destination: PartialSignature = None
    ) -> Generator[ChannelSignature, None, None]:

        return filter_channels(
            self.keys(), source=source, destination=destination
        )
