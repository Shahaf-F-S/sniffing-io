# arp.py

import socket
from dataclasses import dataclass, field
from typing import Iterable

from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
from scapy.packet import Packet

from sniffingio.hub.utils import ether_layer, match_address


__all__ = [
    "ARPPeer",
    "ARPCommunication",
    "ARPState",
    "ARPHub",
    "ARPChannel",
    "ARPData"
]

def arp_layer(packet: Packet) -> ARP:
    if not packet.haslayer(ARP):
        raise ValueError('packet must contain an ARP layer.')

    return packet[ARP]


type SinglePeerSignature = tuple[
    str | set[str] | None,
    str | set[str] | None
]
type Signature = Iterable[SinglePeerSignature]
type joinedSignature = Iterable[
    tuple[SinglePeerSignature, SinglePeerSignature]
]


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class ARPData:

    op: int
    hwsrc: str
    hwdst: str
    psrc: str
    pdst: str

    @classmethod
    def from_packet(cls, packet: Packet) -> ARPData:
        arp = arp_layer(packet)

        return cls(
            op=int(arp.op),
            hwsrc=arp.hwsrc, hwdst=arp.hwdst,
            psrc=arp.psrc, pdst=arp.pdst
        )

    def response(self, payload: str) -> ARPData:
        return response_data(self, payload=payload)

    def to_arp(self) -> ARP | Packet:
        return ARP(
            type=self.op,
            hwsrc=self.hwsrc, hwdst=self.hwdst,
            psrc=self.psrc, pdst=self.pdst
        )

    def match(
        self,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> bool:
        if joined:
            return any(
                match_address(self.hwsrc, s[0]) and
                match_address(self.psrc, s[1]) and
                match_address(self.hwdst, d[0]) and
                match_address(self.pdst, d[1])
                for s, d in joinedSignature
            )

        if source and not any(
            match_address(self.hwsrc, s[0]) and
            match_address(self.psrc, s[1])
            for s in source
        ):
            return False

        if destination and not any(
            match_address(self.hwdst, d[0]) and
            match_address(self.pdst, d[1])
            for d in destination
        ):
            return False

        return True


def response_data(data: Packet | ARPData, payload: str) -> ARPData:
    if not isinstance(data, ARPData):
        data = ARPData.from_packet(data)

    return ARPData(
        op=2, hwsrc=payload, hwdst=data.hwsrc,
        psrc=data.pdst, pdst=data.psrc
    )


def response_packet(packet: Packet, payload: str) -> Packet:
    ether = ether_layer(packet)

    new_ether = Ether(src=ether.dst, dst=ether.src)
    new_arp = response_data(packet, payload=payload).to_arp()

    return new_ether / new_arp


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class ARPPeer:

    signature: tuple[str, str]

    def name(self) -> str:
        return socket.gethostbyaddr(self.ip)[0]

    @property
    def mac(self) -> str:
        return self.signature[0]

    @property
    def ip(self) -> str:
        return self.signature[1]

    @classmethod
    def load(cls, mac: str, ip: str) -> ARPPeer:
        return cls((mac, ip))

    def match(self, signature: Signature) -> bool:
        return (not signature) or any(
            match_address(self.mac, s[0]) and
            match_address(self.ip, s[1])
            for s in signature
        )


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class ARPChannel:

    source: ARPPeer
    destination: ARPPeer

    @classmethod
    def from_packet(cls, packet: Packet) -> ARPChannel:
        ether = ether_layer(packet)
        arp = arp_layer(packet)

        return cls(
            source=ARPPeer((ether.src, arp.psrc)),
            destination=ARPPeer((ether.dst, arp.pdst))
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

    def flip(self) -> ARPChannel:
        return ARPChannel(source=self.destination, destination=self.source)

    def response(self, payload: str, broadcast: bool = False) -> ARPChannel:
        return ARPChannel(
            source=ARPPeer((payload, self.destination.ip)),
            destination=ARPPeer(
                ('ff:ff:ff:ff:ff:ff', '255.255.255.255')
                if broadcast else
                (self.source.mac, self.source.ip)
            )
        )

    def to_ether(self) -> Packet:
        return Ether(src=self.source.mac, dst=self.destination.mac)

    def to_packet(self, op: int) -> Packet:
        return self.to_ether() / ARP(
            op=op,
            hwsrc=self.source.mac,
            hwdst=self.destination.mac,
            psrc=self.source.ip,
            pdst=self.destination.ip
        )


def match_channel_signatures(
    channel: ARPChannel | Packet,
    source: Signature | None = None,
    destination: Signature | None = None,
    joined: joinedSignature = None
) -> bool:
    if not isinstance(channel, ARPChannel):
        channel = ARPChannel.from_packet(channel)

    return channel.match(source, destination, joined)


@dataclass(slots=True, frozen=True, unsafe_hash=True)
class ARPCommunication:

    channel: ARPChannel
    data: ARPData

    @classmethod
    def from_packet(cls, packet: Packet) -> ARPCommunication:
        return cls(
            channel=ARPChannel.from_packet(packet),
            data=ARPData.from_packet(packet)
        )

    def to_packet(self) -> Packet:
        return self.channel.to_ether() / self.data.to_arp()

    def response(self, payload: str, broadcast: bool = False) -> ARPCommunication:
        return ARPCommunication(
            channel=self.channel.response(payload=payload, broadcast=broadcast),
            data=self.data.response(payload=payload)
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
class ARPState:

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
    def arp(self) -> ARP:
        return arp_layer(self.packet)

    def communication(self) -> ARPCommunication:
        return ARPCommunication.from_packet(self.packet)

    def response_packet(self, payload: str) -> Packet:
        return response_packet(self.packet, payload=payload)

    def response_communication(self, payload: str) -> ARPCommunication:
        return self.communication().response(payload=payload)

    def response(self, payload: str) -> ARPState:
        return ARPState(self.response_packet(payload=payload))

    def source(self) -> ARPPeer:
        return ARPPeer((self.ether.src, self.arp.psrc))

    def destination(self) -> ARPPeer:
        return ARPPeer((self.ether.dst, self.arp.pdst))

    def channel(self) -> ARPChannel:
        return ARPChannel(source=self.source(), destination=self.destination())

    def copy(self) -> ARPState:
        return ARPState(self.packet.copy())

    def match(
        self,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> bool:
        return self.channel().match(source, destination, joined)


@dataclass
class ARPHub:

    channels: dict[ARPChannel, ARPState] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.channels)

    def __getitem__(self, key: ARPChannel | Packet) -> ARPState:
        return self.get(key)

    def copy(self) -> ARPHub:
        return ARPHub({key: value.copy() for key, value in self.channels.items()})

    def update(self, hub: ARPHub) -> None:
        self.channels.update(hub.channels)

    def collect(
        self,
        packet: Packet,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> bool:
        key = ARPChannel.from_packet(packet)

        if not key.match(source, destination, joined):
            return False

        self.channels.setdefault(key, ARPState()).collect(packet)

        return True

    def get(self, key: ARPChannel | Packet) -> ARPState:
        if isinstance(key, Packet):
            key = ARPChannel.from_packet(key)

        return self.channels[key]

    def filter(
        self,
        source: Signature = None,
        destination: Signature = None,
        joined: joinedSignature = None
    ) -> Iterable[ARPChannel]:
        for key, value in self.channels.items():
            if key.match(source, destination, joined):
                yield key
