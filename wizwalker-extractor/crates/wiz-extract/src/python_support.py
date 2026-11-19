from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Rva:
    module: str
    rva: int


@dataclass(frozen=True)
class Export:
    module: str
    symbol: str


@dataclass(frozen=True)
class Evidence:
    address: Rva
    data: bytes
    role: str


@dataclass(frozen=True)
class HookDef:
    target: Rva | Export
    overwrite_size: int
    locations: Mapping[str, int]
    dependencies: Mapping[str, Rva | Export]
    evidence: tuple[Evidence, ...]


def _address(fields):
    return Export(**fields) if "symbol" in fields else Rva(**fields)


def _build_hooks(definitions):
    return {
        name: HookDef(
            target=_address(fields["target"]),
            overwrite_size=fields["overwrite_size"],
            locations=fields["locations"],
            dependencies={
                key: _address(address)
                for key, address in fields["dependencies"].items()
            },
            evidence=tuple(
                Evidence(
                    Rva(**item["address"]),
                    bytes.fromhex("".join(item["data"])),
                    item["role"],
                )
                for item in fields["evidence"]
            ),
        )
        for name, fields in definitions.items()
    }
