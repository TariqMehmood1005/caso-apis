# Panels
from PanelsHandler.Panels.lasvegas_sweeps_panel import LasvegasSweepsPanel
from PanelsHandler.Panels.cash_machine_panel import CashMachinePanel
from PanelsHandler.Panels.panda_master_panel import PandaMasterPanel
from PanelsHandler.Panels.orion_stars_panel import OrionStarsPanel
from PanelsHandler.Panels.ultra_panda_panel import UltraPandaPanel
from PanelsHandler.Panels.agent_yolo_panel import AgentYoloPanel
from PanelsHandler.Panels.game_vault_panel import GameVaultPanel
from PanelsHandler.Panels.cash_royal_panel import CashRoyalPanel
from PanelsHandler.Panels.fire_kirin_panel import FireKirinPanel
from PanelsHandler.Panels.game_room_panel import GameRoomPanel
from PanelsHandler.Panels.milky_way_panel import MilkyWayPanel
from PanelsHandler.Panels.vblink_panel import VBlinkPanel
from PanelsHandler.Panels.egame_panel import EGamePanel
from PanelsHandler.Panels.juwa_panel import JuwaPanel

# Others
from playwright.async_api import ProxySettings
from PanelsHandler.utils.logger import AsyncLogger
import threading
import traceback
import asyncio
import psutil
import time
import os


class PanelHandler(object):
    def __init__(
            self,
            headless: bool = True,
            lasvegas_sweeps_panel_username: str = "darkbytes01",
            lasvegas_sweeps_panel_password: str = "AbdulMoez@@5454",
            cash_machine_panel_username: str = "Darkbytes01",
            cash_machine_panel_password: str = "AbdulMoez784",
            panda_master_panel_username: str = "darkbytes",
            panda_master_panel_password: str = "AbdulMoez@@5454",
            orion_star_panel_username: str = "darkbytes",
            orion_star_panel_password: str = "AbdulMoez@@5454",
            ultra_panda_panel_username: str = "DarkBytes",
            ultra_panda_panel_password: str = "AbdulMoez@@5454",
            agent_yolo_panel_username: str = "Darkbytes02",
            agent_yolo_panel_password: str = "AbdulMoez784",
            game_vault_panel_username: str = "DarkBytes",
            game_vault_panel_password: str = "AbdulMoez@@5454",
            cash_royal_panel_username: str = "Darkbytes01",
            cash_royal_panel_password: str = "AbdulMoez@@5454",
            fire_kirin_panel_username: str = "darkbytes",
            fire_kirin_panel_password: str = "AbdulMoez@@5454",
            game_room_panel_username: str = "Darkbytes",
            game_room_panel_password: str = "AbdulMoez784",
            milky_way_panel_username: str = "darkbytes",
            milky_way_panel_password: str = "AbdulMoez@@5454",
            v_blink_panel_username: str = "DarkBytes",
            v_blink_panel_password: str = "AbdulMoez@@5454",
            e_game_panel_username: str = "DarkBytes",
            e_game_panel_password: str = "AbdulMoez@@5454",
            juwa_panel_username: str = "darkbytes01",
            juwa_panel_password: str = "AbdulMoez@@5454",
            enable_js: bool = True,
            logs_backup_count: int = 7,
            timeout: int = 10000,
            num_browsers: int = 2,
            max_browsers: int = 3,
            panel_check_interval_minutes: int = 10,
            interval_minutes: int = 60,  # one hour
            proxy: any([ProxySettings, None]) = None,
            logs_file: str = "PanelsHandler/PanelLogs/panel_handler.log",

    ):
        self.lasvegas_sweeps_panel: LasvegasSweepsPanel = LasvegasSweepsPanel(
            headless=headless,
            panel_username=lasvegas_sweeps_panel_username,
            panel_password=lasvegas_sweeps_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will just create a session
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.cash_machine_panel: CashMachinePanel = CashMachinePanel(
            headless=headless,
            panel_username=cash_machine_panel_username,
            panel_password=cash_machine_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will just create a session
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.panda_master_panel: PandaMasterPanel = PandaMasterPanel(
            headless=headless,
            panel_username=panda_master_panel_username,
            panel_password=panda_master_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=num_browsers,
            max_browsers=max_browsers,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.orion_star_panel: OrionStarsPanel = OrionStarsPanel(
            headless=headless,
            panel_username=orion_star_panel_username,
            panel_password=orion_star_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=num_browsers,
            max_browsers=max_browsers,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.ultra_panda_panel: UltraPandaPanel = UltraPandaPanel(
            headless=headless,
            panel_username=ultra_panda_panel_username,
            panel_password=ultra_panda_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will log out of more than one panel is logged in
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.agent_yolo_panel: AgentYoloPanel = AgentYoloPanel(
            headless=headless,
            panel_username=agent_yolo_panel_username,
            panel_password=agent_yolo_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will just create a session
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.game_vault_panel: GameVaultPanel = GameVaultPanel(
            headless=headless,
            panel_username=game_vault_panel_username,
            panel_password=game_vault_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will just create a session
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.cash_royal_panel: CashRoyalPanel = CashRoyalPanel(
            headless=headless,
            panel_username=cash_royal_panel_username,
            panel_password=cash_royal_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.fire_kirin_panel: FireKirinPanel = FireKirinPanel(
            headless=headless,
            panel_username=fire_kirin_panel_username,
            panel_password=fire_kirin_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=num_browsers,
            max_browsers=max_browsers,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.game_room_panel: GameRoomPanel = GameRoomPanel(
            headless=headless,
            panel_username=game_room_panel_username,
            panel_password=game_room_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will just create a session
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.milky_way_panel: MilkyWayPanel = MilkyWayPanel(
            headless=headless,
            panel_username=milky_way_panel_username,
            panel_password=milky_way_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=num_browsers,
            max_browsers=max_browsers,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.v_blink_panel: VBlinkPanel = VBlinkPanel(
            headless=headless,
            panel_username=v_blink_panel_username,
            panel_password=v_blink_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will log out of more than one panel is logged in
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.e_game_panel: EGamePanel = EGamePanel(
            headless=headless,
            panel_username=e_game_panel_username,
            panel_password=e_game_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will log out of more than one panel is logged in
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.juwa_panel: JuwaPanel = JuwaPanel(
            headless=headless,
            panel_username=juwa_panel_username,
            panel_password=juwa_panel_password,
            enable_js=enable_js,
            logs_backup_count=logs_backup_count,
            timeout=timeout,
            num_browsers=1,  # will just create a session
            max_browsers=1,
            interval_minutes=interval_minutes,
            proxy=proxy
        )
        self.__down_servers: set = set()
        self.check_interval_minutes: int = panel_check_interval_minutes
        self.stop_scheduler: bool = False
        self.__logger = AsyncLogger(
            class_name=self.__class__.__name__,
            log_file=logs_file,
            when="midnight",
            backup_count=logs_backup_count
        )

    def __dict__(self) -> dict[
        str,
        any([
            LasvegasSweepsPanel,
            CashRoyalPanel,
            CashMachinePanel,
            PandaMasterPanel,
            OrionStarsPanel,
            UltraPandaPanel,
            AgentYoloPanel,
            GameRoomPanel,
            GameVaultPanel,
            FireKirinPanel,
            MilkyWayPanel,
            VBlinkPanel,
            EGamePanel,
            JuwaPanel
        ])
    ]:
        return {
            "LASVEGAS_SWEEPS": self.lasvegas_sweeps_panel,
            "CASH_MACHINE": self.cash_machine_panel,
            "CASH_ROYAL": self.cash_royal_panel,
            "PANDA_MASTER": self.panda_master_panel,
            "ORION_STAR": self.orion_star_panel,
            "ULTRA_PANDA": self.ultra_panda_panel,
            "AGENT_YOLO": self.agent_yolo_panel,
            "GAME_VAULT": self.game_vault_panel,
            "FIRE_KIRIN": self.fire_kirin_panel,
            "GAME_ROOM": self.game_room_panel,
            "MILKY_WAY": self.milky_way_panel,
            "V_BLINK": self.v_blink_panel,
            "E_GAME": self.e_game_panel,
            "JUWA": self.juwa_panel
        }

    def __iter__(self):
        for panel_name, panel_object in self.__dict__().items():
            yield panel_name, panel_object

    @staticmethod
    async def __ping_panel(panel):
        response = await panel.ping_game_server()
        return panel, response

    async def __get_initial_panels(self) -> set:
        all_panels = self.__dict__().values()
        ping_tasks = [self.__ping_panel(panel) for panel in all_panels]
        results = await asyncio.gather(*ping_tasks)
        available_panels = set()
        for panel, response in results:
            if response.get('status') == 'active':
                available_panels.add(panel)
            elif response.get('status') == 'inactive':
                self.__down_servers.add(panel)
        return available_panels

    async def get_active_panels(self) -> dict[
        str,
        any([
            LasvegasSweepsPanel,
            CashRoyalPanel,
            CashMachinePanel,
            PandaMasterPanel,
            OrionStarsPanel,
            UltraPandaPanel,
            AgentYoloPanel,
            GameRoomPanel,
            GameVaultPanel,
            FireKirinPanel,
            MilkyWayPanel,
            VBlinkPanel,
            EGamePanel,
            JuwaPanel
        ])
    ]:
        active_panel_dictionary = self.__dict__()
        active_panel_dict = {
            name: panel for name, panel in active_panel_dictionary.items() if panel not in self.__down_servers
        }
        return active_panel_dict

    async def get_down_panels(self) -> dict[
        str,
        any([
            LasvegasSweepsPanel,
            CashRoyalPanel,
            CashMachinePanel,
            PandaMasterPanel,
            OrionStarsPanel,
            UltraPandaPanel,
            AgentYoloPanel,
            GameRoomPanel,
            GameVaultPanel,
            FireKirinPanel,
            MilkyWayPanel,
            VBlinkPanel,
            EGamePanel,
            JuwaPanel
        ])
    ]:
        active_panel_dictionary = self.__dict__()
        down_panels = {
            name: panel for name, panel in active_panel_dictionary.items() if panel in self.__down_servers
        }
        return down_panels

    async def _check_all_panels(self) -> None:
        """Check all panels and update down and up servers accordingly."""
        all_panels = self.__dict__().values()
        ping_tasks = [self.__ping_panel(panel) for panel in all_panels]
        results = await asyncio.gather(*ping_tasks)
        for panel, response in results:
            if response.get('status') == 'active':
                if panel in self.__down_servers:
                    self.__down_servers.remove(panel)
                    try:
                        await panel.initialize_panel()
                    except Exception as e:
                        _ = e
            else:
                self.__down_servers.add(panel)

    async def start_panel_monitor_scheduler(self):
        """Start a scheduler that periodically checks all panels."""
        thread = threading.Thread(target=self._panel_monitor_scheduler_loop, daemon=True)
        thread.start()

    def _panel_monitor_scheduler_loop(self):
        """Scheduler loop running every few minutes."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._panel_monitor_scheduler_async())
        loop.close()

    async def _panel_monitor_scheduler_async(self):
        """Async function to call the initialization every `interval_minutes` minutes.

        This function checks the `self.stop_scheduler` flag every 0.5 seconds to determine
        if it should terminate early. If the scheduler is not stopped, it waits for the
        specified interval before executing the `agent_yolo_related_session` method.
        """
        sleep_seconds = self.check_interval_minutes * 60
        check_interval = 0.5
        while not self.stop_scheduler:
            elapsed = 0.0
            while elapsed < sleep_seconds and not self.stop_scheduler:
                remaining = sleep_seconds - elapsed
                current_sleep = min(check_interval, remaining)
                await asyncio.sleep(current_sleep)
                elapsed += current_sleep
            if self.stop_scheduler:
                break
            try:
                await self._check_all_panels()
            except Exception as e:
                print(f"Error in panel monitor scheduler: {traceback.format_exc()}{e}")

    async def stop_scheduler_function(self):
        """Set the flag to stop the scheduler."""
        self.stop_scheduler = True

    async def initialize_panels(self) -> None:
        start_time = time.time()
        available_panels = await self.__get_initial_panels()
        await self.start_panel_monitor_scheduler()
        total_panels: int = len(available_panels)
        down_panels_dict: dict = await self.get_down_panels()
        if down_panels_dict:
            down_panels: str = ', '.join(list(down_panels_dict.keys()))
            await self.__logger.logs(message=f"INFO: Panels that are currently not responding: {down_panels}")
        for index, panel in enumerate(available_panels):
            try:
                # await asyncio.gather(*initialization_tasks)
                await self.__logger.logs(message=f"INFO: Initializing Panels {index + 1}/{total_panels}")
                await panel.initialize_panel()
            except Exception as e:
                print(f"An error occurred: {traceback.format_exc()}{e}")
        end_time = time.time()
        execution_time_seconds = end_time - start_time
        execution_time_minutes = execution_time_seconds / 60
        print(f"Execution Time: {execution_time_seconds:.2f} seconds")
        print(f"Execution Time: {execution_time_minutes:.2f} minutes")
        process = psutil.Process(os.getpid())
        memory_usage_bytes = process.memory_info().rss
        memory_usage_megabytes = memory_usage_bytes / (1024 * 1024)
        print(f"Memory Usage: {memory_usage_megabytes:.2f} MB")

    async def test_account_creation(self):
        panels_username_passwords = {
            "LASVEGAS_SWEEPS": {"username": "abdulmoez_17", "password": "Test12"},
            "CASH_MACHINE": {"username": "abdulmoez17", "password": "Test12"},
            "CASH_ROYAL": {"username": "abdulmoez_17", "password": "Test12"},
            "PANDA_MASTER": {"username": "abdulmoez_17", "password": "Test_1"},
            "ORION_STAR": {"username": "abdulmoez_17", "password": "Test_1"},
            "ULTRA_PANDA": {"username": "abdulmoez17", "password": "Test@1"},
            "AGENT_YOLO": {"username": "abdulmoez_17", "password": "Test12"},
            "GAME_VAULT": {"username": "abdulmoez_7", "password": "Test12"},
            "FIRE_KIRIN": {"username": "abdulmoez_17", "password": "Test_1"},
            "GAME_ROOM": {"username": "abdulmoez17", "password": "Test12"},
            "MILKY_WAY": {"username": "abdulmoez_17", "password": "Test12"},
            "V_BLINK": {"username": "abdulmoez17", "password": "Test@1"},
            "E_GAME": {"username": "abdulmoez17", "password": "Test@1"},
            "JUWA": {"username": "abdulmoez_17", "password": "Test12"},
        }
        available_panels = await self.get_active_panels()
        for panel_name, panel_instance in available_panels.items():
            await self.__logger.logs(
                message=f'INFO: Creating account for {panel_name}'
            )
            print(await panel_instance.create_player(
                username=panels_username_passwords[panel_name]['username'],
                password=panels_username_passwords[panel_name]['password'],
            ))

    async def test_add_scores(self):
        panels_username_passwords = {
            "LASVEGAS_SWEEPS": {"username": "abdulmoez_17", "password": "Test12"},
            "CASH_MACHINE": {"username": "abdulmoez17", "password": "Test12"},
            "CASH_ROYAL": {"username": "abdulmoez_17", "password": "Test12"},
            "PANDA_MASTER": {"username": "abdulmoez_17", "password": "Test_1"},
            "ORION_STAR": {"username": "abdulmoez_17", "password": "Test_1"},
            "ULTRA_PANDA": {"username": "abdulmoez17", "password": "Test@1"},
            "AGENT_YOLO": {"username": "abdulmoez_17", "password": "Test12"},
            "GAME_VAULT": {"username": "abdulmoez_7", "password": "Test12"},
            "FIRE_KIRIN": {"username": "abdulmoez_17", "password": "Test_1"},
            "GAME_ROOM": {"username": "abdulmoez17", "password": "Test12"},
            "MILKY_WAY": {"username": "abdulmoez_17", "password": "Test12"},
            "V_BLINK": {"username": "abdulmoez17", "password": "Test@1"},
            "E_GAME": {"username": "abdulmoez17", "password": "Test@1"},
            "JUWA": {"username": "abdulmoez_17", "password": "Test12"},
        }
        available_panels = await self.get_active_panels()
        for panel_name, panel_instance in available_panels.items():
            await self.__logger.logs(
                message=f'INFO: Adding 1 score to {panel_name}'
            )
            print(await panel_instance.add_user_score(
                username=panels_username_passwords[panel_name]['username'],
                score=1,
            ))

    async def test_user_scores(self):
        panels_username_passwords = {
            "LASVEGAS_SWEEPS": {"username": "abdulmoez_17", "password": "Test12"},
            "CASH_MACHINE": {"username": "abdulmoez17", "password": "Test12"},
            "CASH_ROYAL": {"username": "abdulmoez_17", "password": "Test12"},
            "PANDA_MASTER": {"username": "abdulmoez_17", "password": "Test_1"},
            "ORION_STAR": {"username": "abdulmoez_17", "password": "Test_1"},
            "ULTRA_PANDA": {"username": "abdulmoez17", "password": "Test@1"},
            "AGENT_YOLO": {"username": "abdulmoez_17", "password": "Test12"},
            "GAME_VAULT": {"username": "abdulmoez_7", "password": "Test12"},
            "FIRE_KIRIN": {"username": "abdulmoez_17", "password": "Test_1"},
            "GAME_ROOM": {"username": "abdulmoez17", "password": "Test12"},
            "MILKY_WAY": {"username": "abdulmoez_17", "password": "Test12"},
            "V_BLINK": {"username": "abdulmoez17", "password": "Test@1"},
            "E_GAME": {"username": "abdulmoez17", "password": "Test@1"},
            "JUWA": {"username": "abdulmoez_17", "password": "Test12"},
        }
        available_panels = await self.get_active_panels()
        for panel_name, panel_instance in available_panels.items():
            await self.__logger.logs(
                message=f'INFO: Getting user score from panel: {panel_name}'
            )
            print(await panel_instance.get_user_scores(
                username=panels_username_passwords[panel_name]['username'],
            ))

    async def test_redeem_scores(self):
        panels_username_passwords = {
            "LASVEGAS_SWEEPS": {"username": "abdulmoez_17", "password": "Test12"},
            "CASH_MACHINE": {"username": "abdulmoez17", "password": "Test12"},
            "CASH_ROYAL": {"username": "abdulmoez_17", "password": "Test12"},
            "PANDA_MASTER": {"username": "abdulmoez_17", "password": "Test_1"},
            "ORION_STAR": {"username": "abdulmoez_17", "password": "Test_1"},
            "ULTRA_PANDA": {"username": "abdulmoez17", "password": "Test@1"},
            "AGENT_YOLO": {"username": "abdulmoez_17", "password": "Test12"},
            "GAME_VAULT": {"username": "abdulmoez_7", "password": "Test12"},
            "FIRE_KIRIN": {"username": "abdulmoez_17", "password": "Test_1"},
            "GAME_ROOM": {"username": "abdulmoez17", "password": "Test12"},
            "MILKY_WAY": {"username": "abdulmoez_17", "password": "Test12"},
            "V_BLINK": {"username": "abdulmoez17", "password": "Test@1"},
            "E_GAME": {"username": "abdulmoez17", "password": "Test@1"},
            "JUWA": {"username": "abdulmoez_17", "password": "Test12"},
        }
        available_panels = await self.get_active_panels()
        for panel_name, panel_instance in available_panels.items():
            await self.__logger.logs(
                message=f'INFO: Removing 1 score from {panel_name}'
            )
            print(await panel_instance.redeem_user_score(
                username=panels_username_passwords[panel_name]['username'],
                score=1,
            ))

    async def test_panel_scores(self):
        available_panels = await self.get_active_panels()
        for panel_name, panel_instance in available_panels.items():
            await self.__logger.logs(
                message=f'INFO: Getting current panels scores from {panel_name}'
            )
            print(await panel_instance.get_panel_balance())

    async def test_reset_passwords(self):
        panels_username_passwords = {
            "LASVEGAS_SWEEPS": {"username": "abdulmoez_17", "password": "Test12"},
            "CASH_MACHINE": {"username": "abdulmoez17", "password": "Test12"},
            "CASH_ROYAL": {"username": "abdulmoez_17", "password": "Test12"},
            "PANDA_MASTER": {"username": "abdulmoez_17", "password": "Test_1"},
            "ORION_STAR": {"username": "abdulmoez_17", "password": "Test_1"},
            "ULTRA_PANDA": {"username": "abdulmoez17", "password": "Test@1"},
            "AGENT_YOLO": {"username": "abdulmoez_17", "password": "Test12"},
            "GAME_VAULT": {"username": "abdulmoez_7", "password": "Test12"},
            "FIRE_KIRIN": {"username": "abdulmoez_17", "password": "Test_1"},
            "GAME_ROOM": {"username": "abdulmoez17", "password": "Test12"},
            "MILKY_WAY": {"username": "abdulmoez_17", "password": "Test12"},
            "V_BLINK": {"username": "abdulmoez17", "password": "Test@1"},
            "E_GAME": {"username": "abdulmoez17", "password": "Test@1"},
            "JUWA": {"username": "abdulmoez_17", "password": "Test12"},
        }
        available_panels = await self.get_active_panels()
        for panel_name, panel_instance in available_panels.items():
            await self.__logger.logs(
                message=f'INFO: Resetting password for user of panel: {panel_name}'
            )
            print(await panel_instance.reset_user_password(
                username=panels_username_passwords[panel_name]['username'],
                new_password=panels_username_passwords[panel_name]['password'],
            ))

    async def close_panels(self):
        await self.stop_scheduler_function()
        try:
            available_panels = await self.__get_initial_panels()
            scheduler_stopping_tasks = [panel.stop_scheduler_function() for panel in available_panels]
            scheduler_stopping_tasks.extend([panel.browser_pool.destroy_pool() for panel in available_panels])
            await asyncio.gather(*scheduler_stopping_tasks)
        except Exception as e:
            print(f"An error occurred: {traceback.format_exc()}{e}")


async def main():
    panel_handles: PanelHandler = PanelHandler(
        headless=True,
        # proxy=ProxySettings(server="http://23.95.150.34:6003", username="kerctuyt", password="qqinspxrxdss")
    )
    await panel_handles.initialize_panels()
    await panel_handles.test_panel_scores()
    await panel_handles.test_account_creation()
    await panel_handles.test_add_scores()
    await panel_handles.test_redeem_scores()
    await panel_handles.test_user_scores()
    await panel_handles.test_reset_passwords()
    await panel_handles.test_panel_scores()
    await asyncio.sleep(10)
    await panel_handles.close_panels()


if __name__ == '__main__':
    asyncio.run(main())

