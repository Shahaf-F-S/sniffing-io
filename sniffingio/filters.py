# filters.py

from typing import Iterable, Callable, ClassVar, Self
from dataclasses import dataclass, asdict, field
from abc import ABCMeta, abstractmethod

from scapy.all import Packet, sniff
from scapy.layers.inet import TCP, UDP


__all__ = [
    "Operand",
    "Layers",
    "Intersection",
    "Operator",
    "Union",
    "Negation",
    "UnionUtils",
    "BaseFilter",
    "StaticFilter",
    "Utils",
    "IntersectionUtils",
    "LivePacketFilter",
    "Values",
    "Names",
    "pf",
    "pfv",
    "load_filters",
    "ip_filter",
    "mac_filter",
    "port_filter"
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


class BaseFilter(UnionUtils, IntersectionUtils, metaclass=ABCMeta):

    @abstractmethod
    def format(self) -> str:
        return ""


@dataclass(slots=True, frozen=True)
class Operand(BaseFilter, metaclass=ABCMeta):

    TYPE: ClassVar[str]
    TYPES: ClassVar[dict[str, type[Operator]]] = {}

    def __init_subclass__(cls, **kwargs) -> None:
        try:
            super().__init_subclass__(**kwargs)

        except TypeError:
            pass

        try:
            cls: type[Operator]
            cls.TYPES.setdefault(cls.TYPE, cls)

        except AttributeError:
            pass

    def __invert__(self) -> "Operand":
        if isinstance(self, Negation):
            return self.filter

        return Negation(self)

    def __or__(self, other) -> "Union":
        if isinstance(other, Operand):
            filters = []

            if isinstance(self, Union):
                filters.extend(self.filters)

            else:
                filters.append(self)

            if isinstance(other, Union):
                filters.extend(other.filters)

            else:
                filters.append(other)

            return Union(tuple(filters))

        return NotImplemented

    def __and__(self, other) -> "Intersection":
        if isinstance(other, Operand):
            filters = []

            if isinstance(self, Intersection):
                filters.extend(self.filters)

            else:
                filters.append(self)

            if isinstance(other, Intersection):
                filters.extend(other.filters)

            else:
                filters.append(other)

            return Intersection(tuple(filters))

        return NotImplemented

    def dump(self) -> dict[str, ...]:
        data = asdict(self)

        data['type'] = self.TYPE

        return data

    @abstractmethod
    def match(self, packet: Packet) -> bool:
        pass


def load_filters(data: dict[str, ...]) -> Operator:
    return Operand.TYPES[data['type']].load(data)


@dataclass(slots=True, frozen=True)
class StaticFilter(Operand):

    filter: str
    TYPE: ClassVar[str] = "static"

    def format(self) -> str:
        return self.filter

    def match(self, packet: Packet) -> bool:
        return len(sniff(offline=packet, filter=self.filter, verbose=0)) > 0


@dataclass(slots=True, frozen=True)
class Operator(Operand, metaclass=ABCMeta):

    filters: tuple[Operand, ...]

    def __len__(self) -> int:
        return len(self.filters)

    @classmethod
    def load(cls, data: dict[str, ...]) -> Self:
        data = data.copy()
        data.pop('type', None)
        data['filters'] = tuple(load_filters(f) for f in data['filters'])

        return cls(**data)

    def dump(self) -> dict[str, ...]:
        data = Operand.dump(self)
        data['filters'] = tuple(f.dump() for f in self.filters)

        return data


@dataclass(slots=True, frozen=True)
class Union(Operator, UnionUtils):

    TYPE: ClassVar[str] = "union"

    def format(self) -> str:
        return self.format_union((f.format() for f in self.filters or ()))

    def match(self, packet: Packet) -> bool:
        return any(f.match(packet) for f in self.filters)


@dataclass(slots=True, frozen=True)
class Intersection(Operator, IntersectionUtils):

    TYPE: ClassVar[str] = "intersection"

    def format(self) -> str:
        return self.format_intersection((f.format() for f in self.filters or ()))

    def match(self, packet: Packet) -> bool:
        return all(f.match(packet) for f in self.filters)


@dataclass(slots=True, frozen=True)
class Negation(Operand):

    filter: Operand
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
        data = Operand.dump(self)
        data['filter'] = self.filter.dump()

        return data


@dataclass(slots=True, frozen=True)
class Values[T](Operand):

    types: set[str] | None = field(default_factory=set)
    names: set[str] | None = field(default_factory=set)
    values: set[T] | None = field(default_factory=set)
    source_values: set[T] | None = field(default_factory=set)
    destination_values: set[T] | None = field(default_factory=set)
    attributes: dict[str, set[T]] | None = field(default_factory=dict)

    TYPE: ClassVar[str] = "values"

    @classmethod
    def load(cls, data: dict[str, ...]) -> "Values[T]":
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
                    for name in self.names
                ),
                (
                    self.format_values(
                        self.source_values, key=' '.join(['src', name])
                    )
                    for name in self.names
                ),
                (
                    self.format_values(
                        self.destination_values, key=' '.join(['dst', name])
                    )
                    for name in self.names
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

            elif isinstance(layer, (TCP, UDP)):
                src = layer.sport
                dst = layer.dport

            else:
                continue

            sources = self.values | self.source_values
            destinations = self.values | self.destination_values

            if (
                (sources and (src not in sources)) or
                (destinations and (dst not in destinations))
            ):
                return False

        return True


@dataclass(slots=True, frozen=True, eq=False)
class Layers(Operand):

    layers: list[Values] = field(default_factory=list)
    TYPE: ClassVar[str] = "packet"

    def match(self, packet: Packet) -> bool:
        layer_filter: Values
        layer: Packet

        for layer, layer_filter in zip(packet.layers(), self.layers):
            if layer_filter is None:
                continue

            if not layer_filter.match(layer):
                return False

        return True

    def format(self) -> str:
        return self.format_intersection(
            layer.format() for layer in self.layers if layer is not None
        )


@dataclass
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


type PF = Layers | Union | Intersection | Negation | StaticFilter | Values

pfv = Values
pf = Layers


def _filter[T: str | int](name: str, values: set[T], src: bool = False, dst: bool = False) -> PF:
    if not (src or dst):
        return Values(names={name}, values=values)

    if src and dst:
        return Values(names={f'src {name}'}, values=values) & Values(names={'dst mac'}, values=values)

    if src:
        return Values(names={f'src {name}'}, values=values)

    else:
        return Values(names={f'dst {name}'}, values=values)


def mac_filter(values: set[str], src: bool = False, dst: bool = False) -> PF:
    return _filter('mac', values, src=src, dst=dst)


def ip_filter(values: set[str], src: bool = False, dst: bool = False) -> PF:
    return _filter('host', values, src=src, dst=dst)


def port_filter(values: set[int], src: bool = False, dst: bool = False) -> PF:
    return _filter('port', values, src=src, dst=dst)
