import hashlib
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch


from wizwalker.errors import MemoryReadError, PatternFailed, PatternMultipleResults
from wizwalker.memory.generated import wiz_hooks
from wizwalker.memory.handler import HookHandler
from wizwalker.memory.hooks import MovementTeleportHook, QuestHook, ServerMoveSnapbackHook
from wizwalker.memory.memory_objects.duel import CurrentDuel


GAME_MODULE = "WizardGraphicalClient.exe"
MODULE_BASE = 0x140000000


class OptionalDropsHookTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.handler = HookHandler(object(), object())
        for name in (
            "player", "quest", "player_stat", "client", "root_window",
            "render_context", "movement_teleport", "drops_toggle", "auto_puzzle",
            "update_zone_counter", "server_move_snapback", "calescent_tracker_active",
            "calescent_tracker_position",
        ):
            setattr(self.handler, f"activate_{name}_hook", AsyncMock())

    async def test_drops_pattern_failures_do_not_block_other_hooks(self):
        for error in (PatternFailed(b"missing"), PatternMultipleResults()):
            with self.subTest(error=type(error).__name__):
                self.handler.activate_drops_toggle_hook.side_effect = error
                self.handler.activate_auto_puzzle_hook.reset_mock()
                self.handler.activate_calescent_tracker_position_hook.reset_mock()

                await self.handler.activate_all_hooks(wait_for_ready=False)

                self.handler.activate_auto_puzzle_hook.assert_awaited_once()
                self.handler.activate_calescent_tracker_position_hook.assert_awaited_once()

    async def test_unexpected_drops_errors_still_propagate(self):
        self.handler.activate_drops_toggle_hook.side_effect = RuntimeError("write failed")

        with self.assertRaisesRegex(RuntimeError, "write failed"):
            await self.handler.activate_all_hooks(wait_for_ready=False)

        self.handler.activate_auto_puzzle_hook.assert_not_awaited()


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

    def install_definition(
        self,
        name,
        rva,
        overwrite_size,
        proof_rva,
        proof_bytes,
        dependencies=None,
    ):
        self.process.memory[MODULE_BASE + proof_rva] = proof_bytes
        entry = wiz_hooks.HookDef(
            target=wiz_hooks.Rva(GAME_MODULE, rva),
            overwrite_size=overwrite_size,
            locations={},
            dependencies=dependencies or {},
            evidence=(wiz_hooks.Evidence(wiz_hooks.Rva(GAME_MODULE, proof_rva), proof_bytes, "test"),),
        )
        patcher = patch.dict(wiz_hooks.HOOKS, {name: entry})
        patcher.start()
        self.addCleanup(patcher.stop)

    def snapback_hook(self):
        patcher = patch.object(
            ServerMoveSnapbackHook, "_verified_game_sha256", wiz_hooks.GAME_SHA256
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        hook = ServerMoveSnapbackHook(self.handler, hook_cache={})
        hook.loaded_module = self.handler.loaded_module
        hook.pattern_scan = AsyncMock(return_value=MODULE_BASE + 0x300)
        self.install_definition(
            hook.generated_name, 0x100, 6, 0x100, hook.generated_original
        )
        return hook

    async def test_snapback_uses_verified_definition_without_scanning(self):
        hook = self.snapback_hook()

        self.assertEqual(await hook._resolve_jump_address(), MODULE_BASE + 0x100)
        self.assertTrue(hook._generated_target)
        hook.pattern_scan.assert_not_awaited()

    async def test_snapback_rejects_modified_live_bytes_without_scanning(self):
        hook = self.snapback_hook()
        self.process.memory[MODULE_BASE + 0x100] = b"\xe9\x00\x00\x00\x00\x90"

        with self.assertRaisesRegex(MemoryReadError, "live bytes=e9 00 00 00 00 90"):
            await hook._resolve_jump_address()

        hook.pattern_scan.assert_not_awaited()

    async def test_snapback_rejects_unverified_payload_build(self):
        hook = self.snapback_hook()

        with patch.object(wiz_hooks, "GAME_SHA256", "unverified-build"):
            with self.assertRaisesRegex(MemoryReadError, "payload has not been validated"):
                await hook._resolve_jump_address()

        hook.pattern_scan.assert_not_awaited()

    async def test_snapback_requires_a_generated_definition(self):
        hook = self.snapback_hook()

        with patch.dict(wiz_hooks.HOOKS, {}, clear=True):
            with self.assertRaisesRegex(MemoryReadError, "requires a generated definition"):
                await hook._resolve_jump_address()

        hook.pattern_scan.assert_not_awaited()

    async def test_snapback_rejects_mismatched_loaded_executable(self):
        hook = self.snapback_hook()
        self.executable.write_bytes(b"different executable")

        with self.assertRaisesRegex(MemoryReadError, "failed build/live-byte validation"):
            await hook._resolve_jump_address()

        hook.pattern_scan.assert_not_awaited()

    async def test_snapback_rejects_an_export_target_with_a_validation_error(self):
        hook = self.snapback_hook()
        definition = replace(
            wiz_hooks.HOOKS[hook.generated_name],
            target=wiz_hooks.Export("user32.dll", "GetCursorPos"),
        )

        with patch.dict(wiz_hooks.HOOKS, {hook.generated_name: definition}):
            with self.assertRaisesRegex(MemoryReadError, "failed build/live-byte validation"):
                await hook._resolve_jump_address()

        hook.pattern_scan.assert_not_awaited()

    async def test_snapback_rechecks_original_bytes_before_installation(self):
        hook = self.snapback_hook()
        hook.jump_address = await hook._resolve_jump_address()
        self.process.memory[MODULE_BASE + 0x100] = bytes(6)
        hook.write_bytes = AsyncMock()

        with self.assertRaisesRegex(MemoryReadError, "changed before installation"):
            await hook._install_jump()

        hook.write_bytes.assert_not_awaited()

    async def test_snapback_installation_uses_verified_resolution(self):
        hook = self.snapback_hook()
        hook.get_hook_address = AsyncMock(return_value=MODULE_BASE + 0x400)
        hook.get_hook_bytecode = AsyncMock(return_value=b"payload")
        hook.get_jump_bytecode = AsyncMock(return_value=b"\xe9\x00\x00\x00\x00\x90")
        hook.write_bytes = AsyncMock()

        await hook.hook()

        self.assertEqual(hook.jump_address, MODULE_BASE + 0x100)
        self.assertEqual(hook.jump_original_bytecode, hook.generated_original)
        hook.get_hook_address.assert_awaited_once_with(75)
        hook.pattern_scan.assert_not_awaited()
        self.assertEqual(hook.write_bytes.await_count, 2)

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

    async def test_movement_uses_the_generated_layout(self):
        original = b"\x57\x48\x83\xEC\x20"
        dependencies = {
            "first_action": wiz_hooks.Rva(GAME_MODULE, 0x200),
            "second_action": wiz_hooks.Rva(GAME_MODULE, 0x210),
            "inside_event": wiz_hooks.Rva(GAME_MODULE, 0x220),
            "event_dispatch": wiz_hooks.Rva(GAME_MODULE, 0x230),
        }
        self.install_definition(
            "movement_teleport",
            0x100,
            len(original),
            0x100,
            original,
            dependencies,
        )
        movement = MovementTeleportHook(self.handler, hook_cache={})
        movement.pattern_scan = AsyncMock(return_value=MODULE_BASE + 0x300)

        self.assertEqual(await movement._resolve_jump_address(), MODULE_BASE + 0x100)
        self.assertEqual(movement._original_instructions, original)
        self.assertEqual(
            await movement.movement_state_branches(),
            (MODULE_BASE + 0x200, MODULE_BASE + 0x210),
        )
        movement.pattern_scan.assert_not_awaited()

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
