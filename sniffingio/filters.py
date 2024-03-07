# filters.py

from typing import Iterable, Callable, ClassVar
from dataclasses import dataclass
from abc import ABCMeta, abstractmethod

from scapy.all import Packet

__all__ = [
    "PacketFilterOperand",
    "PacketFilter",
    "PacketFilterIntersection",
    "PacketFilterOperator",
    "PacketFilterUnion",
    "PacketFilterNegation",
    "BasePacketFilterUnion",
    "BasePacketFilter",
    "StaticPacketFilter",
    "BasePacketFilterOperator",
    "BasePacketFilterIntersection",
    "format_packet_filters",
    "LivePacketFilter",
    "dump_packet_filter",
    "load_packet_filter"
]

class BasePacketFilterOperator(metaclass=ABCMeta):

    @staticmethod
    def format_join(values: Iterable[str], joiner: str) -> str:

        if not values:
            return ""

        return f'({f" {joiner} ".join((value for value in values if value))})'

class BasePacketFilterUnion(BasePacketFilterOperator, metaclass=ABCMeta):

    @classmethod
    def format_union(cls, values: Iterable[str]) -> str:

        return cls.format_join(values, joiner="or")

    @classmethod
    def format_intersection(cls, values: Iterable[str]) -> str:

        return cls.format_join(values, joiner="and")

class BasePacketFilterIntersection(BasePacketFilterOperator, metaclass=ABCMeta):

    @classmethod
    def format_intersection(cls, values: Iterable[str]) -> str:

        return cls.format_join(values, joiner="and")

class BasePacketFilter(
    BasePacketFilterUnion,
    BasePacketFilterIntersection,
    metaclass=ABCMeta
):

    @abstractmethod
    def format(self) -> str:

        return ""

class PacketFilterOperand(BasePacketFilter, metaclass=ABCMeta):

    TYPES: ClassVar[dict[str, list[type["PacketFilterOperand"]]]] = {}
    ATTRIBUTES: ClassVar[set[str]]

    def __init_subclass__(cls, **kwargs) -> None:

        super().__init_subclass__(**kwargs)

        cls.TYPES.setdefault(cls.__name__, []).append(cls)

    def __eq__(self, other: ...) -> bool:

        if (
            not isinstance(other, PacketFilterOperand) or
            (self.ATTRIBUTES != other.ATTRIBUTES)
        ):
            return NotImplemented

        return all(
            getattr(self, key) == getattr(other, key)
            for key in self.ATTRIBUTES
        )

    def __invert__(self) -> "PacketFilterOperand":

        if isinstance(self, PacketFilterNegation):
            return self.filter

        return PacketFilterNegation(self)

    def __or__(self, other: ...) -> "PacketFilterUnion":

        if isinstance(other, PacketFilterOperand):
            return PacketFilterUnion((self, other))

        return NotImplemented

    def __and__(self, other: ...) -> "PacketFilterIntersection":

        if isinstance(other, PacketFilterOperand):
            return PacketFilterIntersection((self, other))

        return NotImplemented

    @classmethod
    def load(cls, data: dict[str, ...]) -> "PacketFilterOperand":

        data = data.copy()

        for key, value in data.items():
            if isinstance(value, dict) and '__type__' in value:
                data[key] = cls.TYPES[data['__type__']][0].load(value)

        return cls.TYPES[data.pop('__type__')][0].load(data)

    def dump(self) -> dict[str, ...]:

        data = {'__type__': type(self).__name__}

        for key in self.ATTRIBUTES:
            value = getattr(self, key)

            if isinstance(value, PacketFilterOperand):
                data[key] = value.dump()

            data[key] = value

        return data

@dataclass(slots=True, frozen=True, eq=False)
class StaticPacketFilter(PacketFilterOperand):

    filter: str

    ATTRIBUTES: ClassVar[set[str]] = {'filter'}

    @classmethod
    def load(cls, data: dict[str, str]) -> "StaticPacketFilter":

        return cls(data['filter'])

    def dump(self) -> dict[str, ...]:

        return {'__type__': type(self).__name__, 'filter': self.filter}

    def format(self) -> str:

        return self.filter

@dataclass(slots=True, frozen=True, eq=False)
class PacketFilterOperator(PacketFilterOperand, metaclass=ABCMeta):

    filters: tuple["PacketFilterOperand", ...]

    ATTRIBUTES: ClassVar[set[str]] = {'filters'}

    def __len__(self) -> int:

        return len(self.filters)

    @classmethod
    def load(cls, data: dict[str, ...]) -> "PacketFilterOperator":

        return cls(
            tuple(
                PacketFilterOperand.load(value)
                for value in data['filters']
            )
        )

    def dump(self) -> dict[str, ...]:

        return {
            '__type__': type(self).__name__,
            'filters': [value.dump() for value in self.filters]
        }

@dataclass(slots=True, frozen=True, eq=False)
class PacketFilterUnion(PacketFilterOperator, BasePacketFilterUnion):

    def format(self) -> str:

        return self.format_union(
            (f.format() for f in self.filters or ())
        )

@dataclass(slots=True, frozen=True, eq=False)
class PacketFilterIntersection(PacketFilterOperator, BasePacketFilterUnion):

    def format(self) -> str:

        return self.format_intersection(
            (f.format() for f in self.filters or ())
        )

@dataclass(slots=True, frozen=True, eq=False)
class PacketFilterNegation(PacketFilterOperand, BasePacketFilterUnion):

    filter: PacketFilterOperand

    ATTRIBUTES: ClassVar[set[str]] = {'filter'}

    def format(self) -> str:

        data = self.filter.format()

        if not data:
            return ""

        return f"(not {data})"

    @classmethod
    def load(cls, data: dict[str, ...]) -> "PacketFilterNegation":

        return cls(PacketFilterOperand.load(data['filter']))

    def dump(self) -> dict[str, ...]:

        return {
            '__type__': type(self).__name__,
            'filter': self.filter.dump()
        }

@dataclass(slots=True, frozen=True, eq=False)
class PacketFilter(PacketFilterOperand):

    protocols: list[str] = None
    source_hosts: list[str] = None
    source_ports: list[int] = None
    destination_hosts: list[str] = None
    destination_ports: list[int] = None

    ATTRIBUTES: ClassVar[set[str]] = {
        'protocols',
        'source_hosts',
        'source_ports',
        'destination_hosts',
        'destination_ports'
    }

    @classmethod
    def format_values(cls, values: Iterable[str], key: str = None) -> str:

        if not values:
            return ""

        return cls.format_union(
            (
                " ".join((key, value) if key else (value, ))
                for value in values
                if value
            )
        )

    @classmethod
    def load(cls, data: dict[str, list[str] | list[int] | None]) -> "PacketFilter":

        return cls(**{key: data.get(key) for key in cls.ATTRIBUTES})

    def dump(self) -> dict[str, list[str] | list[int] | str | None]:

        data = {key: getattr(self, key) for key in self.ATTRIBUTES}
        data['__type__'] = type(self).__name__

        return data

    def format_protocols(self) -> str:

        if not self.protocols:
            return ""

        return self.format_values(
            (protocol.lower() for protocol in self.protocols)
        )

    def format_source_hosts(self) -> str:

        if not self.source_hosts:
            return ""

        return self.format_values(self.source_hosts, key="src host")

    def format_destination_hosts(self) -> str:

        if not self.destination_hosts:
            return ""

        return self.format_values(self.destination_hosts, key="dst host")

    def format_source_ports(self) -> str:

        if not self.source_ports:
            return ""

        return self.format_values(
            (str(port) for port in self.source_ports), key="src port"
        )

    def format_destination_ports(self) -> str:

        if not self.destination_ports:
            return ""

        return self.format_values(
            (str(port) for port in self.destination_ports), key="dst port"
        )

    def format_data(self) -> str:

        data = self.format_intersection(
            (
                data for data in (
                    self.format_protocols(),
                    self.format_source_hosts(),
                    self.format_source_ports(),
                    self.format_destination_hosts(),
                    self.format_destination_ports()
                )
                if data
            )
        )

        if data == "()":
            return ""

        return data

    def format(self) -> str:

        return self.format_data()

def format_packet_filters(
        filters: BasePacketFilter | Iterable[BasePacketFilter],
        joiner: PacketFilterOperator = PacketFilterUnion
) -> str:

    if joiner is None:
        joiner = PacketFilterUnion

    if isinstance(filters, PacketFilterOperand):
        return filters.format()

    return joiner(tuple(filters)).format()

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

def dump_packet_filter(data: PF) -> dict[str, ...]:

    return PacketFilterOperand.dump(data)

def load_packet_filter(data: PF | str | dict[str, ...]) -> PF:

    if isinstance(data, PacketFilterOperand):
        return data

    if isinstance(data, str):
        return StaticPacketFilter(data)

    return PacketFilterOperand.load(data)
