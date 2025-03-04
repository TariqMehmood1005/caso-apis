from asyncio import sleep, new_event_loop, set_event_loop
from playwright.async_api import ProxySettings
from PanelsHandler.utils.BrowserPooling import BrowserPool
from PanelsHandler.utils.logger import AsyncLogger
from datetime import datetime, UTC
from aiohttp import ClientTimeout
import threading
import aiohttp
import inspect
import json
import os
import re


class CashMachinePanel(object):
    """Unofficial API wrapper for the Cash Machine panel handles the API calls and responses"""
    __LOGIN_URL: str = "http://agentserver.cashmachine777.com:8003/admin/login"
    __LANDING_PAGE: str = "http://agentserver.cashmachine777.com:8003/admin"
    __PANEL_SCORE_API: str = "http://agentserver.cashmachine777.com:8003/api/agent/getMoney"
    __ADD_PLAYER_API: str = "http://agentserver.cashmachine777.com:8003/api/player/playerInsert"
    __USER_SCORE_API: str = "http://agentserver.cashmachine777.com:8003/api/player/userList"
    __ADD_SCORE_API: str = "http://agentserver.cashmachine777.com:8003/api/player/agentRecharge"
    __REDEEM_SCORE_API: str = "http://agentserver.cashmachine777.com:8003/api/player/agentWithdraw"
    __RESET_PASSWORD_API: str = "http://agentserver.cashmachine777.com:8003/api/player/reset"

    def __init__(
            self,
            headless: bool = True,
            storage_state_path: str = "PanelsHandler/PanelMemoryFiles/cash_machine_storage.json",
            trained_captcha_solver_model_path: str = "PanelsHandler/TrainedModels/captcha_solver_game_room_0.1.keras",
            logs_file: str = "PanelsHandler/PanelLogs/cash_machine_logs.log",
            logs_backup_count: int = 7,
            panel_username: str = "Darkbytes01",
            panel_password: str = "AbdulMoez784",
            enable_js: bool = True,
            timeout: int = 60000,
            num_browsers: int = 2,
            max_browsers: int = 3,
            interval_minutes: int = 60,  # one hour
            proxy: any([ProxySettings, None]) = None,
    ) -> None:
        self.__timeout: int = timeout
        self.interval_minutes = interval_minutes
        self.stop_scheduler: bool = False
        self.__storage_state_path = os.path.abspath(path=storage_state_path)
        self.__proxy: any([ProxySettings, None]) = proxy
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
            proxy=proxy,
            captcha_max_length=4,
            image_shape=(36, 100)
        )
        self.__logger = AsyncLogger(
            class_name=self.__class__.__name__,
            log_file=logs_file,
            when="midnight",
            backup_count=logs_backup_count
        )

    async def initialize_panel(self):
        await self.__logger.logs(message='INFO: Initializing Panel.')
        if not await self.browser_pool.game_room_related_session():
            await self.__logger.logs(
                message="ERROR: Game Room session does not created.",
                function=inspect.currentframe().f_code.co_name
            )
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
                await self.browser_pool.game_room_related_session()
            except Exception as e:
                print(f"Error: {str(e)}")

    async def ping_game_server(self) -> dict:
        return {
            "status": "active" if await self.browser_pool.ping_server(target_url=self.__LOGIN_URL) else "inactive",
            "pinged_url": self.__LOGIN_URL,
            "datetime": datetime.now(tz=UTC).__str__(),
        }

    async def __load_auth_data(self) -> tuple[dict, dict]:
        while not os.path.isfile(path=self.__storage_state_path):
            await self.stop_scheduler_function()
            await self.initialize_panel()
        with open(file=self.__storage_state_path, mode='r') as data_file:
            temp_data: dict = json.load(fp=data_file)
            cookies = {cookie['name']: cookie['value'] for cookie in temp_data["cookies"]}
            auth_token = temp_data["auth_token"]
            headers: dict = {
                "Authorization": f"Bearer {auth_token}"
            }
            return cookies, headers

    @staticmethod
    async def __is_valid_username(username: str) -> bool:
        pattern = r"^[A-Za-z\d]{3,12}$"
        return bool(re.match(pattern, username))

    @staticmethod
    async def __is_valid_password(password: str) -> bool:
        """
        Validates that the password length is between 6 and 24 characters.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        pattern = r"^[^\s]{6,12}$"
        return bool(re.match(pattern, password))

    async def create_player(self, username: str, password: str, nickname: str = "") -> dict:
        """This function takes the username, password and nickname of the new user and crated it on the panel using
        the browse automation and returns True if user created otherwise False if we encounter any errors."""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Username must be between 3 and 12 characters long and contain only letters and numbers",
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
                'message': "Password must be 6 to 12 characters long and cannot contain spaces.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                    "nickname": nickname,
                    "score": 0
                }
            }
        payloads = {
            "username": username,
            "nickname": nickname,
            "money": "0",
            "password": password,
            "password_confirmation": password
        }
        cookies, headers = await self.__load_auth_data()
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.post(
                    url=self.__ADD_PLAYER_API,
                    headers=headers,
                    cookies=cookies,
                    data=payloads
            ) as response:
                if response.status == 200:
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
                else:
                    await self.__logger.logs(
                        message=f"ERROR: Unexpected error: {await response.text()}",
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

    async def get_panel_balance(self) -> dict:
        """get the balance available in the panel so that we can make sure in agent panel that this game gets
        enough balance"""
        cookies, headers = await self.__load_auth_data()
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.post(
                    url=self.__PANEL_SCORE_API,
                    headers=headers,
                    cookies=cookies
            ) as response:
                if response.status == 200:
                    json_data = await response.json()
                    return {
                        'status': 200,
                        'message': "Successfully fetched panel scores.",
                        "data": {
                            "datetime": datetime.now(tz=UTC).__str__(),
                            'score': int(float(json_data['data']))
                        }
                    }
                else:
                    await self.__logger.logs(
                        message=f"ERROR: Unexpected error: {await response.text()}",
                        function=inspect.currentframe().f_code.co_name
                    )
                    return {
                        'status': 500,
                        'message': "Unable to get panel scores. Please try again after few minutes.",
                        "data": {
                            "datetime": datetime.now(tz=UTC).__str__(),
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
                'message': "Password must be 6 to 12 characters long and cannot contain spaces.",
                "data": {
                    "username": username,
                    "newpassword": new_password,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        parameters = {
            "page": "1",
            "limit": "60",
            "account": username,
            "nickname": "",
            "Id": ""
        }
        cookies, headers = await self.__load_auth_data()
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    params=parameters
            ) as response:
                if response.status == 200:
                    json_data = await response.json()
                    for user in json_data['data']:
                        if user['Account'] == username:
                            user_id = user['Id']
                            payloads = {
                                "id": user_id,
                                "password": new_password,
                                "password_confirmation": new_password
                            }
                            async with session.post(
                                    url=self.__RESET_PASSWORD_API,
                                    headers=headers,
                                    cookies=cookies,
                                    data=payloads
                            ) as reset_password_response:
                                if reset_password_response.status == 200:
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
                                    await self.__logger.logs(
                                        message=f"ERROR: Unable to reset user password: {
                                        await reset_password_response.text()
                                        }",
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
                else:
                    await self.__logger.logs(
                        message=f"ERROR: Unexpected error: {await response.text()}",
                        function=inspect.currentframe().f_code.co_name
                    )
                    return {
                        'status': 500,
                        'message': "Unable to find user. Please try again after few minutes.",
                        "data": {
                            "username": username,
                            "newpassword": new_password,
                            "datetime": datetime.now(tz=UTC).__str__(),
                        }
                    }
        await self.__logger.logs(
            message="DEBUG: Unable to find user. No result return.",
            function=inspect.currentframe().f_code.co_name
        )
        return {
            'status': 422,
            'message': "Unable to find user. Please create user first.",
            "data": {
                "username": username,
                "newpassword": new_password,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
        }

    async def redeem_user_score(self, username: str, score: int) -> dict:
        """If the user wants to get the score into money we will redeem score and add money to their wallet"""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Invalid username.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        parameters = {
            "page": "1",
            "limit": "60",
            "account": username,
            "nickname": "",
            "Id": ""
        }
        cookies, headers = await self.__load_auth_data()
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    params=parameters
            ) as response:
                if response.status == 200:
                    json_data = await response.json()
                    for user in json_data['data']:
                        if user['Account'] == username:
                            user_id = user['Id']
                            current_user_balance: int = int(user['score'])
                            if current_user_balance >= score:
                                payloads = {
                                    "id": user_id,
                                    "customer_balance": str(current_user_balance),
                                    "opera_type": "1",
                                    "balance": str(score),
                                    'remark': ''
                                }
                                async with session.post(
                                        url=self.__REDEEM_SCORE_API,
                                        headers=headers,
                                        cookies=cookies,
                                        data=payloads
                                ) as redeem_response:
                                    if redeem_response.status == 200:
                                        return {
                                            'status': 200,
                                            'message': "Score successfully redeemed scores from the game.",
                                            "data": {
                                                "username": username,
                                                "new_scores": current_user_balance - score,
                                                "datetime": datetime.now(tz=UTC).__str__(),
                                            }
                                        }
                                    else:
                                        await self.__logger.logs(
                                            message=f"ERROR: Unable to redeem score from the game: {
                                            await redeem_response.text()
                                            }",
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
                            else:
                                return {
                                    'status': 422,
                                    'message': "You don't have enough scores to redeem.",
                                    "data": {
                                        "username": username,
                                        "current_score": int(current_user_balance),
                                        "datetime": datetime.now(tz=UTC).__str__(),
                                    }
                                }
                else:
                    await self.__logger.logs(
                        message=f"ERROR: Unexpected error: {await response.text()}",
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
        await self.__logger.logs(
            message="DEBUG: Unable to find user. No result return.",
            function=inspect.currentframe().f_code.co_name
        )
        return {
            'status': 422,
            'message': "Unable to find user. Please create user first.",
            "data": {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
        }

    async def get_user_scores(self, username: str) -> dict:
        """Get the current score of the user"""
        parameters = {
            "page": "1",
            "limit": "60",
            "account": username,
            "nickname": "",
            "Id": ""
        }
        cookies, headers = await self.__load_auth_data()
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    params=parameters
            ) as response:
                if response.status == 200:
                    json_data = await response.json()
                    for user in json_data['data']:
                        if user['Account'] == username:
                            current_user_balance: int = int(user['score'])
                            return {
                                'status': 200,
                                'message': "Score successfully fetch from the game.",
                                "data": {
                                    "username": username,
                                    "score": int(current_user_balance),
                                    "datetime": datetime.now(tz=UTC).__str__(),
                                }
                            }
                else:
                    await self.__logger.logs(
                        message=f"ERROR: Unexpected error: {await response.text()}",
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
        await self.__logger.logs(
            message="DEBUG: Unable to find user. No result return.",
            function=inspect.currentframe().f_code.co_name
        )
        return {
            'status': 422,
            'message': "Unable to find user. Please create user first.",
            "data": {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
        }

    async def add_user_score(self, username: str, score: int) -> dict:
        """We can assign them more scores and deduct the money from their wallets"""
        parameters = {
            "page": "1",
            "limit": "60",
            "account": username,
            "nickname": "",
            "Id": ""
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
        cookies, headers = await self.__load_auth_data()
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    params=parameters
            ) as response:
                if response.status == 200:
                    json_data = await response.json()
                    for user in json_data['data']:
                        if user['Account'] == username:
                            user_id = user['Id']
                            current_user_balance: int = int(user['score'])
                            payloads = {
                                "id": user_id,
                                "available_balance": panel_scores['data']['score'],
                                "opera_type": "0",
                                "bonus": "0",
                                "balance": score,
                                'remark': ''
                            }
                            async with session.post(
                                    url=self.__ADD_SCORE_API,
                                    headers=headers,
                                    cookies=cookies,
                                    data=payloads
                            ) as add_response:
                                if add_response.status == 200:
                                    return {
                                        'status': 200,
                                        'message': "Score successfully added to the game.",
                                        "data": {
                                            "username": username,
                                            "new_scores": int(current_user_balance) + score,
                                            "datetime": datetime.now(tz=UTC).__str__(),
                                        }
                                    }
                                else:
                                    await self.__logger.logs(
                                        message=f"ERROR: Unable to add scores to the game: {
                                        await add_response.text()
                                        }",
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
                else:
                    await self.__logger.logs(
                        message=f"ERROR: Unexpected error: {await response.text()}",
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
        await self.__logger.logs(
            message="DEBUG: Unable to find user. No result return.",
            function=inspect.currentframe().f_code.co_name
        )
        return {
            'status': 422,
            'message': "Unable to find user. Please create user first.",
            "data": {
                "username": username,
                "datetime": datetime.now(tz=UTC).__str__(),
            }
        }

