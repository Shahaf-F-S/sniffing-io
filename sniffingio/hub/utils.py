# utils.py

from scapy.packet import Packet
from scapy.layers.inet import Ether


__all__ = [
    'ether_layer',
    'match_address'
]


def ether_layer(packet: Packet) -> Ether:
    if not packet.haslayer(Ether):
        raise ValueError('packet must contain an Ether layer.')

    return packet[Ether]


def match_address(address: str, signature: str | set[str] | None) -> bool:
    if signature is None:
        return True

    if isinstance(signature, str):
        return address == signature

    return address in signature
