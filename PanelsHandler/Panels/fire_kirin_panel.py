from playwright.async_api import Page, ElementHandle, ProxySettings
from asyncio import sleep, new_event_loop, set_event_loop
from PanelsHandler.utils.BrowserPooling import BrowserPool
from PanelsHandler.utils.logger import AsyncLogger
from datetime import datetime, UTC
import threading
import traceback
import inspect


class FireKirinPanel(object):
    """Unofficial API wrapper for the Fire Kirin panel handles the API calls and responses"""
    __LOGIN_URL: str = "https://firekirin.xyz:8888/default.aspx"
    __LANDING_PAGE: str = "https://firekirin.xyz:8888/Store.aspx"

    def __init__(
            self,
            headless: bool = True,
            storage_state_path: str = "PanelsHandler/PanelMemoryFiles/fire_kirin_storage.json",
            trained_captcha_solver_model_path: str = "PanelsHandler/TrainedModels/captcha_solver_v1.keras",
            panel_username: str = "darkbytes",
            panel_password: str = "AbdulMoez@@5454",
            enable_js: bool = True,
            logs_file: str = "PanelsHandler/PanelLogs/fire_kirin_logs.log",
            logs_backup_count: int = 7,
            timeout: int = 30000,
            num_browsers: int = 2,
            max_browsers: int = 10,
            interval_minutes: int = 60,  # one hour
            proxy: any([ProxySettings, None]) = None,
    ) -> None:
        self.__timeout: int = timeout
        self.interval_minutes = interval_minutes
        self.stop_scheduler: bool = False
        self.browser_pool: BrowserPool = BrowserPool(
            login_page_url=self.__LOGIN_URL,
            landing_page_url=self.__LANDING_PAGE,
            num_browsers=num_browsers,
            max_browsers=max_browsers,
            storage_state_path=storage_state_path,
            trained_captcha_solver_model_path=trained_captcha_solver_model_path,
            panel_password=panel_password,
            panel_username=panel_username,
            enable_js=enable_js,
            timeout=timeout,
            headless=headless,
            proxy=proxy
        )
        self.__logger = AsyncLogger(
            class_name=self.__class__.__name__,
            log_file=logs_file,
            when="midnight",
            backup_count=logs_backup_count
        )

    async def initialize_panel(self):
        await self.__logger.logs(message='INFO: Initializing Panel.')
        await self.browser_pool.initialize_pool()
        if self.stop_scheduler:
            self.stop_scheduler = True
            await sleep(delay=1)
            await self.start_scheduler()
        else:
            await self.start_scheduler()
        await self.__logger.logs(message='INFO: Panel Initialized successfully.')

    async def start_scheduler(self):
        """Start the scheduler in a separate thread."""
        thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        thread.start()

    async def stop_scheduler_function(self):
        """Set flag to stop the scheduler."""
        self.stop_scheduler = True

    def _scheduler_loop(self):
        """Scheduler loop running every 30 minutes."""
        loop = new_event_loop()
        set_event_loop(loop)
        loop.run_until_complete(self._scheduler_async())
        loop.close()

    async def _scheduler_async(self):
        """Async function to call the initialization every `interval_minutes` minutes.

        This function checks the `self.stop_scheduler` flag every 0.5 seconds to determine
        if it should terminate early. If the scheduler is not stopped, it waits for the
        specified interval before executing the `agent_yolo_related_session` method.
        """
        sleep_seconds = self.interval_minutes * 60
        check_interval = 0.5
        while not self.stop_scheduler:
            elapsed = 0.0
            while elapsed < sleep_seconds and not self.stop_scheduler:
                remaining = sleep_seconds - elapsed
                current_sleep = min(check_interval, remaining)
                await sleep(current_sleep)
                elapsed += current_sleep
            if self.stop_scheduler:
                break
            try:
                await self.browser_pool.create_session()
                await self.browser_pool.update_pool()
            except Exception as e:
                print(f"Error: {str(e)}")

    async def ping_game_server(self) -> dict:
        return {
            "status": "active" if await self.browser_pool.ping_server(target_url=self.__LOGIN_URL) else "inactive",
            "pinged_url": self.__LOGIN_URL,
            "datetime": datetime.now(tz=UTC).__str__(),
        }

    @staticmethod
    async def __is_valid_username(username: str) -> bool:
        if len(username) > 13:
            return False
        for char in username:
            if not (char.isalnum() or char == '_'):
                return False
        return True

    @staticmethod
    async def __is_valid_password(password: str) -> bool:
        for char in password:
            if not (char.isalnum() or char == '_'):
                return False
        return True

    async def create_player(self, username: str, password: str, nickname: str = "") -> dict:
        """This function takes the username, password and nickname of the new user and crated it on the panel using
        the browse automation and returns True if user created otherwise False if we encounter any errors."""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Username must be 13 characters or fewer. It must include letters, underscores, "
                           "and numbers.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                    "nickname": nickname,
                    "score": 0
                }
            }
        if not await self.__is_valid_password(password=password):
            return {
                'status': 400,
                'message': "Password must include letters, underscores, and numbers.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                    "nickname": nickname,
                    "score": 0
                }
            }
        raw_response = await self.browser_pool.get_available_browser()
        browser_id: int = raw_response[-1]
        response = raw_response[0]
        browser_page: Page = response[2]
        try:
            player_iframe = browser_page.frame_locator(selector='iframe[name="frm_main_content"]')
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"] + a + a').click()
            create_player_frame = browser_page.frame_locator(selector='iframe[src*="CreateAccount.aspx"]')
            await create_player_frame.locator(selector_or_locator='input[name="txtAccount"]').fill(value=username)
            await create_player_frame.locator(selector_or_locator='input[name="txtNickName"]').fill(value=nickname)
            await create_player_frame.locator(selector_or_locator='input[name="txtLogonPass"]').fill(value=password)
            await create_player_frame.locator(selector_or_locator='input[name="txtLogonPass2"]').fill(value=password)
            await create_player_frame.locator(selector_or_locator='a[class="btn13 btn-danger1"]').click()
            element: ElementHandle = await browser_page.wait_for_selector(selector='input[id="mb_btn_ok"]')
            await element.click()
        except Exception as e:
            full_error = f"ERROR: {traceback.format_exc()}\n{e}"
            await self.browser_pool.release_browser(index=browser_id)
            await self.__logger.logs(
                message=f"ERROR: Unexpected error: {full_error}",
                function=inspect.currentframe().f_code.co_name
            )
            return {
                'status': 500,
                'message': "User not created. Please try again after few minutes.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                    "nickname": nickname,
                    "score": 0
                }
            }
        await self.browser_pool.release_browser(index=browser_id)
        return {
            'status': 200,
            'message': "User Created successfully",
            "data": {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
                "nickname": nickname,
                "score": 0
            }
        }

    async def get_panel_balance(self) -> dict:
        """get the balance available in the panel so that we can make sure in agent panel that this game gets
        enough balance"""
        raw_response = await self.browser_pool.get_available_browser()
        browser_id: int = raw_response[-1]
        response = raw_response[0]
        browser_page: Page = response[2]
        try:
            # await browser_page.reload(wait_until="domcontentloaded")
            # For not I am replacing the reload function with selector clicking
            # because the panel scores are not appearing when page gets reloaded (issue in panel)
            await browser_page.wait_for_selector(
                selector='iframe[src="Left.aspx"]',
                timeout=self.__timeout
            )
            await browser_page.frame_locator(
                selector='iframe[src="Left.aspx"]'
            ).locator(
                selector_or_locator='a[onclick*="/Module/AccountManager/AccountsList.aspx"]',
            ).click()
            element: ElementHandle = await browser_page.wait_for_selector(
                selector='span[id="UserBalance"]',
                timeout=self.__timeout
            )
            raw_balance: str = await element.text_content()
            panel_balance = int(raw_balance.split(":")[1].strip())
        except Exception as e:
            full_error = f"ERROR: {traceback.format_exc()}\n{e}"
            await self.browser_pool.release_browser(index=browser_id)
            await self.__logger.logs(
                message=f"ERROR: Unexpected error: {full_error}",
                function=inspect.currentframe().f_code.co_name
            )
            return {
                'status': 500,
                'message': "Unable to get panel scores. Please try again after few minutes.",
                "data": {
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        await self.browser_pool.release_browser(index=browser_id)
        return {
            'status': 200,
            'message': "Successfully fetched panel scores.",
            "data": {
                "datetime": datetime.now(tz=UTC).__str__(),
                'score': panel_balance
            }
        }

    async def reset_user_password(self, username: str, new_password: str) -> dict:
        """Reset the password if the user forget his/her password, and we can assign them new password"""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Invalid username.",
                "data": {
                    "username": username,
                    "newpassword": new_password,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        if not await self.__is_valid_password(password=new_password):
            return {
                'status': 400,
                'message': "Password must include letters, underscores, and numbers.",
                "data": {
                    "username": username,
                    "newpassword": new_password,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        raw_response = await self.browser_pool.get_available_browser()
        browser_id: int = raw_response[-1]
        response = raw_response[0]
        browser_page: Page = response[2]
        try:
            player_iframe = browser_page.frame_locator(selector='iframe[name="frm_main_content"]')
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"]').fill(value=username)
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"] + a').click()
            await player_iframe.locator(
                'div[class="SearchBg2"] > table tr[class="list"]'
            ).first.wait_for(state="visible")
            available_players = await player_iframe.locator(
                selector_or_locator='div[class="SearchBg2"] > table tr[class="list"]').all()
            found_player = False
            for player in available_players:
                player_username: str = await player.locator(selector_or_locator='td').nth(2).text_content()
                if player_username.strip() == username:
                    await player.locator(selector_or_locator='td > a').click()
                    found_player = True
                    break
            if found_player:
                await player_iframe.locator(
                    selector_or_locator='a[onclick*="Reset Password"]'
                ).wait_for(state="visible")
                await player_iframe.locator(selector_or_locator='a[onclick*="Reset Password"]').click()
                treasure_iframe = browser_page.frame_locator(selector='iframe[src*="ResetPassWord.aspx"]')
                await treasure_iframe.locator(
                    selector_or_locator='input[name="txtConfirmPass"]'
                ).wait_for(state="visible")
                await treasure_iframe.locator(
                    selector_or_locator='input[name="txtConfirmPass"]'
                ).fill(value=new_password)
                await treasure_iframe.locator(selector_or_locator='input[name="txtSureConfirmPass"]').fill(
                    value=new_password
                )
                await treasure_iframe.locator(selector_or_locator='input[value="Reset"]').wait_for(state="visible")
                await treasure_iframe.locator(selector_or_locator='input[value="Reset"]').click()
                element: ElementHandle = await browser_page.wait_for_selector(
                    selector='input[id="mb_btn_ok"]', timeout=self.__timeout
                )
                await element.click()
                element: ElementHandle = await browser_page.wait_for_selector(
                    selector='span[id="Close"]', timeout=self.__timeout
                )
                await element.click()
                await self.browser_pool.release_browser(index=browser_id)
                return {
                    'status': 200,
                    'message': "Password reset successfully.",
                    "data": {
                        "username": username,
                        "newpassword": new_password,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }
            else:
                await self.browser_pool.release_browser(index=browser_id)
                return {
                    'status': 422,
                    'message': "Unable to find user. Please create user first.",
                    "data": {
                        "username": username,
                        "newpassword": new_password,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }
        except Exception as e:
            full_error = f"ERROR: {traceback.format_exc()}\n{e}"
            await self.browser_pool.release_browser(index=browser_id)
            await self.__logger.logs(
                message=f"ERROR: Unexpected error: {full_error}",
                function=inspect.currentframe().f_code.co_name
            )
            return {
                'status': 422,
                'message': "Unable to reset the password.",
                "data": {
                    "username": username,
                    "newpassword": new_password,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }

    async def redeem_user_score(self, username: str, score: int) -> dict:
        """If the user want to get the score into money we will redeem score and add money to their wallet"""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Invalid username.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        raw_response = await self.browser_pool.get_available_browser()
        browser_id: int = raw_response[-1]
        response = raw_response[0]
        browser_page: Page = response[2]
        try:
            player_iframe = browser_page.frame_locator(selector='iframe[name="frm_main_content"]')
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"]').fill(value=username)
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"] + a').click()
            await player_iframe.locator(
                'div[class="SearchBg2"] > table tr[class="list"]'
            ).first.wait_for(state="visible")
            available_players = await player_iframe.locator(
                selector_or_locator='div[class="SearchBg2"] > table tr[class="list"]').all()
            found_player = False
            for player in available_players:
                player_username: str = await player.locator(selector_or_locator='td').nth(2).text_content()
                if player_username.strip() == username:
                    await player.locator(selector_or_locator='td > a').click()
                    found_player = True
                    break
            if found_player:
                await player_iframe.locator(selector_or_locator='a[onclick*="Redeem"]').wait_for(state="visible")
                await player_iframe.locator(selector_or_locator='a[onclick*="Redeem"]').click()
                treasure_iframe = browser_page.frame_locator(selector='iframe[src*="ChangeTreasure.aspx"]')
                await treasure_iframe.locator(selector_or_locator='input[name="txtAddGold"]').wait_for(state="visible")
                await treasure_iframe.locator(selector_or_locator='input[name="txtAddGold"]').fill(value=str(score))
                current_score_raw: str = await treasure_iframe.locator(
                    selector_or_locator='input[name="txtLeScore"]').get_attribute(name="value")
                current_treasure = int(float(current_score_raw.strip()))
                if current_treasure >= score:
                    await treasure_iframe.locator(selector_or_locator='input[value="Redeem"]').wait_for(state="visible")
                    await treasure_iframe.locator(selector_or_locator='input[value="Redeem"]').click()
                    element: ElementHandle = await browser_page.wait_for_selector(
                        selector='input[id="mb_btn_ok"]', timeout=self.__timeout
                    )
                    await element.click()
                    element: ElementHandle = await browser_page.wait_for_selector(
                        selector='span[id="Close"]', timeout=self.__timeout
                    )
                    await element.click()
                    player_credits = current_treasure - score
                    await self.browser_pool.release_browser(index=browser_id)
                    return {
                        'status': 200,
                        'message': "Score successfully redeemed scores from the game.",
                        "data": {
                            "username": username,
                            "new_scores": player_credits,
                            "datetime": datetime.now(tz=UTC).__str__(),
                        }
                    }
                else:
                    element: ElementHandle = await browser_page.wait_for_selector(
                        selector='span[id="Close"]',
                        timeout=self.__timeout
                    )
                    await element.click()
                    await self.browser_pool.release_browser(index=browser_id)
                    return {
                        'status': 422,
                        'message': "You don't have enough scores to redeem.",
                        "data": {
                            "username": username,
                            "current_score": int(current_treasure),
                            "datetime": datetime.now(tz=UTC).__str__(),
                        }
                    }
            else:
                await self.browser_pool.release_browser(index=browser_id)
                return {
                    'status': 422,
                    'message': "Unable to find user. Please create a user first.",
                    "data": {
                        "username": username,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }

        except Exception as e:
            full_error = f"ERROR: {traceback.format_exc()}\n{e}"
            await self.browser_pool.release_browser(index=browser_id)
            await self.__logger.logs(
                message=f"ERROR: Unexpected error: {full_error}",
                function=inspect.currentframe().f_code.co_name
            )
            return {
                'status': 422,
                'message': "Unable to redeem scores from the game.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }

    async def add_user_score(self, username: str, score: int) -> dict:
        """We can assign them more scores and deduct the money from their wallets"""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Invalid username.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        panel_scores = await self.get_panel_balance()
        if 'score' in panel_scores['data']:
            if not panel_scores['data']['score'] >= score:
                return {
                    'status': 500,
                    'message': "Not enough Panel scores please contact our agents..",
                    "data": {
                        "username": username,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }
        else:
            return {
                'status': 500,
                'message': "Unable to get Panel scores please contact our agents.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        raw_response = await self.browser_pool.get_available_browser()
        browser_id: int = raw_response[-1]
        response = raw_response[0]
        browser_page: Page = response[2]
        try:
            player_iframe = browser_page.frame_locator(selector='iframe[name="frm_main_content"]')
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"]').fill(value=username)
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"] + a').click()
            await player_iframe.locator(
                'div[class="SearchBg2"] > table tr[class="list"]'
            ).first.wait_for(state="visible")
            available_players = await player_iframe.locator(
                selector_or_locator='div[class="SearchBg2"] > table tr[class="list"]').all()
            found_player = False
            for player in available_players:
                player_username: str = await player.locator(selector_or_locator='td').nth(2).text_content()
                if player_username.strip() == username:
                    await player.locator(selector_or_locator='td > a').click()
                    found_player = True
                    break
            if found_player:
                await player_iframe.locator(selector_or_locator='a[onclick*="Recharge"]').wait_for(state="visible")
                await player_iframe.locator(selector_or_locator='a[onclick*="Recharge"]').click()
                treasure_iframe = browser_page.frame_locator(selector='iframe[src*="GrantTreasure.aspx"]')
                await treasure_iframe.locator(selector_or_locator='input[name="txtAddGold"]').wait_for(state="visible")
                await treasure_iframe.locator(selector_or_locator='input[name="txtAddGold"]').fill(value=str(score))
                current_score_raw: str = await treasure_iframe.locator(
                    selector_or_locator='input[name="txtLeScore"]'
                ).get_attribute(name="value")
                current_score = int(float(current_score_raw.strip()))
                await treasure_iframe.locator(selector_or_locator='input[value="Recharge"]').wait_for(state="visible")
                await treasure_iframe.locator(selector_or_locator='input[value="Recharge"]').click()
                element: ElementHandle = await browser_page.wait_for_selector(
                    selector='input[id="mb_btn_ok"]', timeout=self.__timeout
                )
                await element.click()
                element: ElementHandle = await browser_page.wait_for_selector(
                    selector='span[id="Close"]', timeout=self.__timeout
                )
                await element.click()
                player_credits = current_score + score
                await self.browser_pool.release_browser(index=browser_id)
                return {
                    'status': 200,
                    'message': "Score successfully added to the game.",
                    "data": {
                        "username": username,
                        "new_scores": player_credits,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }
            else:
                await self.browser_pool.release_browser(index=browser_id)
                return {
                    'status': 422,
                    'message': "Unable to find user. Please create user first.",
                    "data": {
                        "username": username,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }
        except Exception as e:
            full_error = f"ERROR: {traceback.format_exc()}\n{e}"
            await self.browser_pool.release_browser(index=browser_id)
            await self.__logger.logs(
                message=f"ERROR: Unexpected error: {full_error}",
                function=inspect.currentframe().f_code.co_name
            )
            return {
                'status': 422,
                'message': "Unable to add score to the game.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }

    async def get_user_scores(self, username: str) -> dict:
        """Get the current score of the user"""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Invalid username.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        raw_response = await self.browser_pool.get_available_browser()
        browser_id: int = raw_response[-1]
        response = raw_response[0]
        browser_page: Page = response[2]
        try:
            player_iframe = browser_page.frame_locator(selector='iframe[name="frm_main_content"]')
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"]').fill(value=username)
            await player_iframe.locator(selector_or_locator='input[name="txtSearch"] + a').click()
            await player_iframe.locator(
                'div[class="SearchBg2"] > table tr[class="list"]'
            ).first.wait_for(state="visible")
            available_players = await player_iframe.locator(
                selector_or_locator='div[class="SearchBg2"] > table tr[class="list"]').all()
            found_player = False
            for player in available_players:
                player_username: str = await player.locator(selector_or_locator='td').nth(2).text_content()
                if player_username.strip() == username:
                    await player.locator(selector_or_locator='td > a').click()
                    found_player = True
                    break
            if found_player:
                await player_iframe.locator(
                    selector_or_locator='span[id="txtBalance"]'
                ).wait_for(state="visible")
                await sleep(.9)
                player_credits_raw: str = await player_iframe.locator(
                    selector_or_locator='span[id="txtBalance"]'
                ).text_content()
                if not player_credits_raw:
                    await sleep(.2)
                    player_credits_raw: str = await player_iframe.locator(
                        selector_or_locator='span[id="txtBalance"]'
                    ).text_content()
                player_credits = int(float(player_credits_raw.strip()))
                await self.browser_pool.release_browser(index=browser_id)
                return {
                    'status': 200,
                    'message': "Score successfully fetch from the game.",
                    "data": {
                        "username": username,
                        "score": int(player_credits),
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }
            else:
                await self.browser_pool.release_browser(index=browser_id)
                return {
                    'status': 422,
                    'message': "Unable to find user. Please create user first.",
                    "data": {
                        "username": username,
                        "datetime": datetime.now(tz=UTC).__str__(),
                    }
                }
        except Exception as e:
            full_error = f"ERROR: {traceback.format_exc()}\n{e}"
            await self.browser_pool.release_browser(index=browser_id)
            await self.__logger.logs(
                message=f"ERROR: Unexpected error: {full_error}",
                function=inspect.currentframe().f_code.co_name
            )
            return {
                'status': 500,
                'message': "Unable to find user. Please try again after few minutes.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }



