import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch


from wizwalker.errors import MemoryReadError
from wizwalker.memory.generated import wiz_hooks
from wizwalker.memory.handler import HookHandler
from wizwalker.memory.hooks import QuestHook
from wizwalker.memory.memory_objects.duel import CurrentDuel


GAME_MODULE = "WizardGraphicalClient.exe"
MODULE_BASE = 0x140000000


class FixtureProcess:
    def __init__(self):
        self.memory = {}

    def read_bytes(self, address, size):
        return self.memory[address][:size]


class GeneratedHooksTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        executable = Path(directory.name) / GAME_MODULE
        data = b"test executable"
        executable.write_bytes(data)
        patcher = patch.object(wiz_hooks, "GAME_SHA256", hashlib.sha256(data).hexdigest())
        patcher.start()
        self.addCleanup(patcher.stop)

        self.executable = executable
        self.process = FixtureProcess()
        self.handler = HookHandler(self.process, object())
        self.handler.loaded_module = AsyncMock(
            return_value=SimpleNamespace(filename=str(executable), lpBaseOfDll=MODULE_BASE)
        )
        self.quest = QuestHook(self.handler, hook_cache={})
        self.quest.pattern_scan = AsyncMock(return_value=MODULE_BASE + 0x300)

    def install_definition(self, name, rva, overwrite_size, proof_rva, proof_bytes):
        self.process.memory[MODULE_BASE + proof_rva] = proof_bytes
        entry = wiz_hooks.HookDef(
            target=wiz_hooks.Rva(GAME_MODULE, rva),
            overwrite_size=overwrite_size,
            locations={},
            dependencies={},
            evidence=(wiz_hooks.Evidence(wiz_hooks.Rva(GAME_MODULE, proof_rva), proof_bytes, "test"),),
        )
        patcher = patch.dict(wiz_hooks.HOOKS, {name: entry})
        patcher.start()
        self.addCleanup(patcher.stop)

    async def test_quest_uses_verified_definition_and_replayed_span(self):
        original = self.quest.generated_original
        self.install_definition("core.quest", 0x102, len(original), 0x100, b"\x90\x90" + original)

        self.assertEqual(await self.quest._resolve_jump_address(), MODULE_BASE + 0x102)
        self.assertEqual(self.quest.instruction_length, len(original))
        self.quest.pattern_scan.assert_not_awaited()

    async def test_mismatched_live_bytes_use_legacy_scan(self):
        original = self.quest.generated_original
        self.install_definition("core.quest", 0x100, len(original), 0x100, original)
        self.assertEqual(await self.quest._resolve_jump_address(), MODULE_BASE + 0x100)
        self.process.memory[MODULE_BASE + 0x100] = bytes(len(original))

        self.assertEqual(await self.quest._resolve_jump_address(), MODULE_BASE + 0x300)
        self.assertEqual(self.quest.instruction_length, QuestHook.instruction_length)
        self.quest.pattern_scan.assert_awaited_once()

    async def test_mismatched_executable_uses_legacy_scan(self):
        original = self.quest.generated_original
        self.install_definition("core.quest", 0x100, len(original), 0x100, original)
        self.executable.write_bytes(b"updated build")

        self.assertEqual(await self.quest._resolve_jump_address(), MODULE_BASE + 0x300)
        self.quest.pattern_scan.assert_awaited_once()

    async def test_changed_bytes_abort_before_installation(self):
        original = self.quest.generated_original
        self.install_definition("core.quest", 0x100, len(original), 0x100, original)
        self.quest.jump_address = await self.quest._resolve_jump_address()
        self.process.memory[self.quest.jump_address] = bytes(len(original))
        self.quest.write_bytes = AsyncMock()

        with self.assertRaises(MemoryReadError):
            await self.quest._install_jump()
        self.quest.write_bytes.assert_not_awaited()

    async def test_duel_reads_pointer_from_the_generated_slot(self):
        self.install_definition("combat.duel_manager", 0x200, 0, 0x100, b"pointer load")
        duel = CurrentDuel(self.handler)
        duel.read_typed = AsyncMock(return_value=0x1234)
        self.handler.pattern_scan = AsyncMock()

        with patch("wizwalker.memory.memory_objects.client_duel_manager.DynamicClientDuelManager") as manager:
            manager.return_value.duelmap = AsyncMock(return_value={})
            self.assertEqual(await duel.read_base_address(), 0)
        self.assertEqual(duel.read_typed.await_args.args[0], MODULE_BASE + 0x200)
        self.handler.pattern_scan.assert_not_awaited()

    async def test_autobot_uses_the_generated_region_without_scanning_or_writing(self):
        self.install_definition("autobot", 0x400, 0, 0x400, b"autobot entry")
        self.handler.pattern_scan = AsyncMock()
        self.handler.write_bytes = AsyncMock()

        await self.handler._get_autobot_address()

        self.assertEqual(self.handler._autobot_address, MODULE_BASE + 0x400)
        self.handler.pattern_scan.assert_not_awaited()
        self.handler.write_bytes.assert_not_awaited()
