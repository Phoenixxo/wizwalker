from dataclasses import dataclass
from hashlib import file_digest
from typing import Mapping

from wizwalker.errors import MemoryReadError

from .generated import wiz_hooks


@dataclass(frozen=True)
class ResolvedHook:
    target: int
    original: bytes
    dependencies: Mapping[str, int]
    locations: Mapping[str, int]


@dataclass(frozen=True)
class _ValidatedDefinition:
    definition: wiz_hooks.HookDef
    target: int
    dependencies: Mapping[str, int]


class GeneratedHookResolver:
    """Check the game build and live bytes before using a generated address."""

    def __init__(self):
        self._matches_build = None

    async def resolve(
        self, reader, name: str, *, original: bytes | None = None
    ) -> int | None:
        validated = await self._validate_definition(reader, name)
        if validated is None:
            return None

        definition = validated.definition
        if original is None:
            if definition.overwrite_size != 0:
                return None
        elif len(original) > definition.overwrite_size or not any(
            proof.address.module == definition.target.module
            and (offset := definition.target.rva - proof.address.rva) >= 0
            and proof.data[offset : offset + len(original)] == original
            for proof in definition.evidence
        ):
            return None
        return validated.target

    async def resolve_layout(self, reader, name: str) -> ResolvedHook | None:
        validated = await self._validate_definition(reader, name)
        if validated is None:
            return None

        definition = validated.definition
        if definition.overwrite_size < 5:
            return None

        original = next(
            (
                proof.data[offset : offset + definition.overwrite_size]
                for proof in definition.evidence
                if proof.address.module == definition.target.module
                and (offset := definition.target.rva - proof.address.rva) >= 0
                and len(proof.data) - offset >= definition.overwrite_size
            ),
            None,
        )
        if original is None:
            return None

        return ResolvedHook(
            target=validated.target,
            original=original,
            dependencies=validated.dependencies,
            locations=definition.locations,
        )

    async def _validate_definition(
        self, reader, name: str
    ) -> _ValidatedDefinition | None:
        definition = wiz_hooks.HOOKS.get(name)
        if (
            definition is None
            or not isinstance(definition.target, wiz_hooks.Rva)
            or definition.target.module != "WizardGraphicalClient.exe"
            or not definition.evidence
        ):
            return None

        module = await reader.loaded_module(definition.target.module)
        if module is None:
            return None

        if self._matches_build is None:
            self._matches_build = await reader.run_in_executor(
                self._has_matching_hash, module.filename
            )
        if not self._matches_build:
            return None

        base = module.lpBaseOfDll
        try:
            for proof in definition.evidence:
                if proof.address.module != definition.target.module:
                    return None
                actual = await reader.read_bytes(
                    base + proof.address.rva, len(proof.data)
                )
                if actual != proof.data:
                    return None
        except MemoryReadError:
            return None

        dependencies = {}
        for dependency_name, address in definition.dependencies.items():
            if (
                not isinstance(address, wiz_hooks.Rva)
                or address.module != definition.target.module
            ):
                return None
            dependencies[dependency_name] = base + address.rva

        return _ValidatedDefinition(
            definition=definition,
            target=base + definition.target.rva,
            dependencies=dependencies,
        )

    @staticmethod
    def _has_matching_hash(path: str) -> bool:
        try:
            with open(path, "rb") as executable:
                return file_digest(executable, "sha256").hexdigest() == wiz_hooks.GAME_SHA256
        except OSError:
            return False
