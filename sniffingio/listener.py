# listener.py

import socket
from dataclasses import dataclass, field
from typing import Iterable

from scapy.layers.inet import IP, TCP, Ether
from scapy.packet import Raw, Packet


__all__ = [
    "response_data",
    "response_packet",
    "next_data",
    "next_packet",
    "Peer",
    "TCPCommunication",
    "State",
    "TCPHub",
    "Channel",
    "TCPData"
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


type SinglePeerSignature = tuple[
    str | set[str] | None,
    str | set[str] | None,
    int | set[int] | tuple[int, int] | None
]
type SingleFlaggedPeerSignature = SinglePeerSignature | tuple[
    str | set[str] | None,
    str | set[str] | None,
    int | set[int] | tuple[int, int] | None,
    str | set[str] | None
]
type Signature = Iterable[SingleFlaggedPeerSignature]
type joinedSignature = Iterable[
    tuple[SingleFlaggedPeerSignature, SingleFlaggedPeerSignature]
]


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


def match_flag_signatures(
    flags: str | TCP | Packet,
    source: Signature = None,
    destination: Signature = None,
    joined: joinedSignature = None
) -> bool:
    if isinstance(flags, Packet):
        flags = tcp_layer(flags)

    if isinstance(flags, TCP):
        flags = flags.flags

    flags = str(flags)

    if joined:
        return any(
            ((len(s) < 4) or match_flags(flags, signature=s[3])) and
            ((len(d) < 4) or match_flags(flags, signature=d[3]))
            for s, d in joined
        )

    if source and not any(
        (len(s) < 4) or match_flags(flags, signature=s[3])
        for s in (source or ())
    ):
        return False

    if destination and not any(
        (len(s) < 4) or match_flags(flags, signature=s[3])
        for s in (destination or ())
    ):
        return False

    return True


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
            ack=tcp.ack, seq=tcp.seq, flags=str(tcp.flags),
            payload=packet[Raw].load if str(tcp.flags) == 'PA' else None
        )

    def response(self, flags: str = None, payload: bytes = None) -> TCPData:
        return response_data(self, flags=flags, payload=payload)

    def next(self, flags: str = None, payload: bytes = None) -> TCPData:
        return next_data(self, flags=flags, payload=payload)

    def to_tcp(self, source: int, destination: int) -> TCP | Packet:
        tcp = TCP(
            sport=source, dport=destination,
            ack=self.ack, seq=self.seq, flags=self.flags
        )

        if self.payload:
            tcp = tcp / self.payload

        return tcp

    def match(
        self,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> bool:
        return match_flag_signatures(self.flags, source, destination, joined)


def response_data(data: Packet | TCPData, flags: str = None, payload: bytes = None) -> TCPData:
    if flags is None and payload:
        flags = 'PA'

    elif flags is None:
        flags = 'A'

    if not isinstance(data, TCPData):
        data = TCPData.from_packet(data)

    return TCPData(
        ack=data.seq + len(data.payload or b''),
        seq=data.ack, flags=flags, payload=payload
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
        ack=data.ack, flags=flags, payload=payload
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


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Peer:

    signature: tuple[str, str, int]

    def name(self) -> str:
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

    def match(self, signature: Signature) -> bool:
        return (not signature) or any(
            match_address(self.mac, s[0]) and
            match_address(self.ip, s[1]) and
            match_port(self.port, s[2])
            for s in signature
        )


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class Channel:

    source: Peer
    destination: Peer

    @classmethod
    def from_packet(cls, packet: Packet) -> Channel:
        ether = ether_layer(packet)
        ip = ip_layer(packet)
        tcp = tcp_layer(packet)

        return cls(
            source=Peer((ether.src, ip.src, tcp.sport)),
            destination=Peer((ether.dst, ip.dst, tcp.dport))
        )

    def match(
        self,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> bool:
        if joined:
            return any(
                self.source.match((s,)) and self.destination.match((d,))
                for s, d in joined
            )

        return self.source.match(source) and self.destination.match(destination)

    def flip(self) -> Channel:
        return Channel(source=self.destination, destination=self.source)

    def to_packet(self) -> Packet:
        return (
            Ether(src=self.source.mac, dst=self.destination.mac) /
            IP(src=self.source.ip, dst=self.destination.ip)
        )


def match_channel_signatures(
    channel: Channel | Packet,
    source: Signature | None = None,
    destination: Signature | None = None,
    joined: joinedSignature = None
) -> bool:
    if not isinstance(channel, Channel):
        channel = Channel.from_packet(channel)

    return channel.match(source, destination, joined)


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class TCPCommunication:

    channel: Channel
    data: TCPData

    @classmethod
    def from_packet(cls, packet: Packet) -> TCPCommunication:
        return cls(
            channel=Channel.from_packet(packet),
            data=TCPData.from_packet(packet)
        )

    def to_tcp(self) -> TCP | Packet:
        return self.data.to_tcp(
            source=self.channel.source.port,
            destination=self.channel.destination.port
        )

    def to_packet(self) -> Packet:
        return self.channel.to_packet() / self.to_tcp()

    def response(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return TCPCommunication(
            channel=self.channel.flip(),
            data=self.data.response(flags=flags, payload=payload)
        )

    def next(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return TCPCommunication(
            channel=self.channel,
            data=self.data.next(flags=flags, payload=payload)
        )

    def match(
        self,
        source: Signature | None = None,
        destination: Signature | None = None,
        joined: joinedSignature = None
    ) -> bool:
        return (
            self.data.match(source, destination, joined) and
            self.channel.match(source, destination, joined)
        )


@dataclass(slots=True)
class State:

    _data: Packet = None

    def __hash__(self):
        return hash(bytes(self.packet))

    def collect(
        self,
        packet: Packet,
        source: Signature | None = None,
        destination: Signature | None = None,
        joined: joinedSignature = None
    ) -> bool:
        if (source, destination, joined) != (None, None, None):
            if not match_flag_signatures(packet, source, destination, joined):
                return False

            if not match_channel_signatures(packet, source, destination, joined):
                return False

        # noinspection PyDunderSlots,PyUnresolvedReferences
        self._data = packet

        return True

    @property
    def packet(self) -> Packet:
        if self._data is None:
            raise ValueError('No packet was collected.')

        return self._data

    @property
    def ether(self) -> Ether:
        return ether_layer(self.packet)

    @property
    def ip(self) -> IP:
        return ip_layer(self.packet)

    @property
    def tcp(self) -> TCP:
        return tcp_layer(self.packet)

    def communication(self) -> TCPCommunication:
        return TCPCommunication.from_packet(self.packet)

    def response_packet(self, flags: str = None, payload: bytes = None) -> Packet:
        return response_packet(self.packet, flags=flags, payload=payload)

    def next_packet(self, flags: str = None, payload: bytes = None) -> Packet:
        return next_packet(self.packet, flags=flags, payload=payload)

    def response_communication(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return self.communication().response(flags=flags, payload=payload)

    def next_communication(self, flags: str = None, payload: bytes = None) -> TCPCommunication:
        return self.communication().next(flags=flags, payload=payload)

    def response(self, flags: str = None, payload: bytes = None) -> State:
        return State(self.response_packet(flags=flags, payload=payload))

    def next(self, flags: str = None, payload: bytes = None) -> State:
        return State(self.next_packet(flags=flags, payload=payload))

    def source(self) -> Peer:
        return Peer((self.ether.src, self.ip.src, self.tcp.sport))

    def destination(self) -> Peer:
        return Peer((self.ether.dst, self.ip.dst, self.tcp.dport))

    def channel(self) -> Channel:
        return Channel(source=self.source(), destination=self.destination())

    def copy(self) -> State:
        return State(self.packet.copy())

    def match(
        self,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> bool:
        return (
            self.channel().match(source, destination, joined) and
            match_flag_signatures(self.tcp.flags, source, destination, joined)
        )


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
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> bool:
        if not match_flag_signatures(packet, source, destination, joined):
            return False

        key = Channel.from_packet(packet)

        if not key.match(source, destination, joined):
            return False

        self.channels.setdefault(key, State()).collect(packet)

        return True

    def get(self, key: Channel | Packet) -> State:
        if isinstance(key, Packet):
            key = Channel.from_packet(key)

        return self.channels[key]

    def filter(
        self,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> Iterable[Channel]:
        for key, value in self.channels.items():
            if (
                match_flag_signatures(value.tcp, source, destination, joined) and
                key.match(source, destination, joined)
            ):
                yield key
