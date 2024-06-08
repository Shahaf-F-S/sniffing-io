# filters.py

from typing import Iterable, Callable, ClassVar, Self
from dataclasses import dataclass, asdict
from abc import ABCMeta, abstractmethod

from scapy.all import Packet, sniff

__all__ = [
    "PacketFilterOperand",
    "PacketFilter",
    "PacketFilterIntersection",
    "PacketFilterOperator",
    "PacketFilterUnion",
    "PacketFilterNegation",
    "UnionUtils",
    "BasePacketFilter",
    "StaticPacketFilter",
    "Utils",
    "IntersectionUtils",
    "LivePacketFilter",
    "PacketFilterValues",
    "Names",
    "pf",
    "pfv",
    "load_filters"
]

def wrap(value: str) -> str:

    if (" " in value) and not (value.startswith("(") and value.endswith(")")):
        value = f"({value})"

    return value

class Names:

    IP = 'ip'
    HOST = 'host'
    PORT = 'port'
    SRC = 'src'
    DST = 'dst'
    ETHER = 'ether'
    NET = 'net'
    MASK = 'mask'
    TCP = 'tcp'
    UDP = 'udp'
    ICMP = 'icmp'
    SMTP = 'smtp'
    MAC = 'mac'
    PORT_RANGE = 'portrange'
    LESS = 'less'
    GREATER = 'greater'
    PROTO = 'proto'
    BROADCAST = 'broadcast'
    MULTICAST = 'multicast'
    VLAN = 'vlan'
    MPLS = 'mpls'
    ARP = 'arp'
    FDDI = 'fddi'
    IP6 = 'ip6'
    LINK = 'link'
    PPP = 'ppp'
    RADIO = 'radio'
    RARP = 'rarp'
    SLIP = 'slip'
    TR = 'tr'
    WLAN = 'wlan'

class Utils(metaclass=ABCMeta):

    @staticmethod
    def format_join(values: Iterable[str], joiner: str) -> str:

        if not values:
            return ""

        values = tuple(str(value) for value in values)

        if len(values) == 1:
            return wrap(values[0])

        data = f" {joiner} ".join(wrap(value) for value in values if value)

        return f"({data})"

class UnionUtils(Utils, metaclass=ABCMeta):

    @classmethod
    def format_union(cls, values: Iterable[str]) -> str:

        return cls.format_join(values, joiner="or")

class IntersectionUtils(Utils, metaclass=ABCMeta):

    @classmethod
    def format_intersection(cls, values: Iterable[str]) -> str:

        return cls.format_join(values, joiner="and")

class BasePacketFilter(UnionUtils, IntersectionUtils, metaclass=ABCMeta):

    @abstractmethod
    def format(self) -> str:

        return ""

@dataclass(slots=True, frozen=True)
class PacketFilterOperand(BasePacketFilter, metaclass=ABCMeta):

    TYPE: ClassVar[str]
    TYPES: ClassVar[dict[str, type["PF"]]] = {}

    def __init_subclass__(cls, **kwargs) -> None:

        try:
            super().__init_subclass__(**kwargs)

        except TypeError:
            pass

        try:
            cls.TYPES.setdefault(cls.TYPE, cls)

        except AttributeError:
            pass

    def __invert__(self) -> "PacketFilterOperand":

        if isinstance(self, PacketFilterNegation):
            return self.filter

        return PacketFilterNegation(self)

    def __or__(self, other: ...) -> "PacketFilterUnion":

        if isinstance(other, PacketFilterOperand):
            filters = []

            if isinstance(self, PacketFilterUnion):
                filters.extend(self.filters)

            else:
                filters.append(self)

            if isinstance(other, PacketFilterUnion):
                filters.extend(other.filters)

            else:
                filters.append(other)

            return PacketFilterUnion(tuple(filters))

        return NotImplemented

    def __and__(self, other: ...) -> "PacketFilterIntersection":

        if isinstance(other, PacketFilterOperand):
            filters = []

            if isinstance(self, PacketFilterIntersection):
                filters.extend(self.filters)

            else:
                filters.append(self)

            if isinstance(other, PacketFilterIntersection):
                filters.extend(other.filters)

            else:
                filters.append(other)

            return PacketFilterIntersection(tuple(filters))

        return NotImplemented

    def dump(self) -> dict[str, ...]:

        data = asdict(self)

        data['type'] = self.TYPE

        return data

    @abstractmethod
    def match(self, packet: Packet) -> bool:

        pass

def load_filters(data: dict[str, ...]) -> "PF":

    return PacketFilterOperand.TYPES[data['type']].load(data)

@dataclass(slots=True, frozen=True)
class StaticPacketFilter(PacketFilterOperand):

    filter: str

    TYPE: ClassVar[str] = "static"

    def format(self) -> str:

        return self.filter

    def match(self, packet: Packet) -> bool:

        return len(sniff(offline=packet, filter=self.filter, verbose=0)) > 0

@dataclass(slots=True, frozen=True)
class PacketFilterOperator(PacketFilterOperand, metaclass=ABCMeta):

    filters: tuple[PacketFilterOperand, ...]

    def __len__(self) -> int:

        return len(self.filters)

    @classmethod
    def load(cls, data: dict[str, ...]) -> Self:

        data = data.copy()
        data.pop('type', None)

        data['filters'] = tuple(load_filters(f) for f in data['filters'])

        return cls(**data)

    def dump(self) -> dict[str, ...]:

        data = PacketFilterOperand.dump(self)

        data['filters'] = tuple(f.dump() for f in self.filters)

        return data

@dataclass(slots=True, frozen=True)
class PacketFilterUnion(PacketFilterOperator, UnionUtils):

    TYPE: ClassVar[str] = "union"

    def format(self) -> str:

        return self.format_union((f.format() for f in self.filters or ()))

    def match(self, packet: Packet) -> bool:

        return any(f.match(packet) for f in self.filters)

@dataclass(slots=True, frozen=True)
class PacketFilterIntersection(PacketFilterOperator, IntersectionUtils):

    TYPE: ClassVar[str] = "intersection"

    def format(self) -> str:

        return self.format_intersection((f.format() for f in self.filters or ()))

    def match(self, packet: Packet) -> bool:

        return all(f.match(packet) for f in self.filters)

@dataclass(slots=True, frozen=True)
class PacketFilterNegation(PacketFilterOperand):

    filter: PacketFilterOperand

    TYPE: ClassVar[str] = "negation"

    def format(self) -> str:

        data = self.filter.format()

        if not data:
            return ""

        return f"(not {data})"

    def match(self, packet: Packet) -> bool:

        return not self.filter.match(packet)

    @classmethod
    def load(cls, data: dict[str, ...]) -> Self:

        data = data.copy()
        data.pop('type', None)

        data['filter'] = load_filters(data['filter'])

        return cls(**data)

    def dump(self) -> dict[str, ...]:

        data = PacketFilterOperand.dump(self)

        data['filter'] = self.filter.dump()

        return data

@dataclass(slots=True, frozen=True)
class PacketFilterValues[T](PacketFilterOperand):

    types: list[str] | None = None
    names: list[str] | None = None
    values: list[T] | None = None
    source_values: list[T] | None = None
    destination_values: list[T] | None = None
    attributes: dict[str, list[T]] | None = None

    TYPE: ClassVar[str] = "values"

    @classmethod
    def load(cls, data: dict[str, ...]) -> "PacketFilterValues[T]":

        data = data.copy()
        data.pop('type', None)

        return cls(**data)

    @classmethod
    def format_values(cls, values: Iterable[str], key: str = None) -> str:

        if not values:
            return ""

        return cls.format_union(
            (
                " ".join((key, str(value)) if key else (str(value),))
                for value in values
                if value
            )
        )

    def format(self) -> str:

        values = [
            self.format_union(values)
            for values in (
                self.types,
                (
                    self.format_values(self.values, key=name)
                    for name in self.names or ['']
                ),
                (
                    self.format_values(
                        self.source_values, key=' '.join(['src', name])
                    )
                    for name in self.names or ['']
                ),
                (
                    self.format_values(
                        self.destination_values, key=' '.join(['dst', name])
                    )
                    for name in self.names or ['']
                )
            )
            if values
        ]

        values = [value for value in values if value]

        return self.format_intersection(values)

    def match(self, packet: Packet) -> bool:

        for layer in packet.layers():
            if (
                (self.types is not None) and
                (layer.name.lower() not in {n.lower() for n in self.types})
            ):
                return False

            if (
                self.attributes and
                not all(
                    hasattr(packet, attr) and
                    getattr(packet, attr) in values
                    for attr, values in self.attributes.items()
                )
            ):
                return False

            if hasattr(layer, 'src'):
                src = layer.src
                dst = layer.dst

            elif hasattr(layer, 'sport'):
                src = layer.sport
                dst = layer.dport

            else:
                continue

            sources = (self.values or []) + (self.source_values or [])
            destinations = (self.values or []) + (self.destination_values or [])

            if (
                (sources and (src not in sources)) or
                (destinations and (dst not in destinations))
            ):
                return False

        return True

@dataclass(slots=True, frozen=True, eq=False)
class PacketFilter(PacketFilterOperand):

    layers: list[PacketFilterValues] = None

    TYPE: ClassVar[str] = "packet"

    def match(self, packet: Packet) -> bool:

        for layer, layer_filter in zip(packet.layers(), self.layers):
            if layer_filter is None:
                continue

            layer_filter: PacketFilterValues

            if not layer_filter.match(layer):
                return False

        return True

    def format(self) -> str:

        return self.format_intersection(
            layer.format() for layer in self.layers if layer is not None
        )

@dataclass(slots=True)
class LivePacketFilter:

    validator: Callable[[Packet], bool]

    disabled: bool = False

    def __call__(self, *args, **kwargs) -> bool:

        return self.validate(*args, **kwargs)

    def disable(self) -> None:

        self.disabled = True

    def enable(self) -> None:

        self.disabled = False

    def validate(self, packet: Packet) -> bool:

        if self.disabled:
            return True

        result = self.validator(packet)

        return result

PF = (
    PacketFilter |
    PacketFilterUnion |
    PacketFilterIntersection |
    PacketFilterNegation |
    StaticPacketFilter
)

pfv = PacketFilterValues
pf = PacketFilter
