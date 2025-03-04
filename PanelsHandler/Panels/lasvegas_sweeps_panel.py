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


class LasvegasSweepsPanel(object):
    """Unofficial API wrapper for the Lasvegas Sweeps panel handles the API calls and responses"""
    __LOGIN_URL: str = "https://agent.lasvegassweeps.com/login"
    __LANDING_PAGE: str = "https://agent.lasvegassweeps.com/userManagement"
    __PANEL_SCORE_API: str = "https://agent.lasvegassweeps.com/api/agent/balance"
    __ADD_PLAYER_API: str = "https://agent.lasvegassweeps.com/api/user/addUser"
    __USER_SCORE_API: str = "https://agent.lasvegassweeps.com/api/user/userList"
    __ADD_SCORE_API: str = "https://agent.lasvegassweeps.com/api/user/rechargeRedeem"
    __REDEEM_SCORE_API: str = "https://agent.lasvegassweeps.com/api/user/rechargeRedeem"
    __RESET_PASSWORD_API: str = "https://agent.lasvegassweeps.com/api/user/resetUserPwd"

    def __init__(
            self,
            headless: bool = True,
            storage_state_path: str = "PanelsHandler/PanelMemoryFiles/lasvegas_sweeps_storage.json",
            trained_captcha_solver_model_path: str = "PanelsHandler/TrainedModels/captcha_solver_lasvegas_sweeps_0.1.keras",
            panel_username: str = "darkbytes01",
            panel_password: str = "AbdulMoez@@5454",
            enable_js: bool = True,
            timeout: int = 10000,
            num_browsers: int = 2,
            logs_file: str = "PanelsHandler/PanelLogs/e_game_logs.log",
            logs_backup_count: int = 7,
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
            image_shape=(62, 200),
            captcha_solver_vocab=['0', '2', '3', '4', '5', '6', '8', '9']
        )
        self.__logger = AsyncLogger(
            class_name=self.__class__.__name__,
            log_file=logs_file,
            when="midnight",
            backup_count=logs_backup_count
        )

    async def initialize_panel(self):
        await self.__logger.logs(message='INFO: Initializing Panel.')
        if not await self.browser_pool.game_vault_related_session():
            await self.__logger.logs(
                message="ERROR: Game Vault session does not created.",
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
                await self.browser_pool.game_vault_related_session()
            except Exception as e:
                print(f"Error: {str(e)}")

    async def ping_game_server(self) -> dict:
        return {
            "status": "active" if await self.browser_pool.ping_server(target_url=self.__LOGIN_URL) else "inactive",
            "pinged_url": self.__LOGIN_URL,
            "datetime": datetime.now(tz=UTC).__str__(),
        }

    async def __load_auth_data(self) -> tuple[dict, dict, dict]:
        while not os.path.isfile(path=self.__storage_state_path):
            await self.stop_scheduler_function()
            await self.initialize_panel()
        with open(file=self.__storage_state_path, mode='r') as data_file:
            temp_data: dict = json.load(fp=data_file)
            cookies = {cookie['name']: cookie['value'] for cookie in temp_data["cookies"]}
            headers = {
                "Authorization": f"Bearer {temp_data['token']}"
            }
            return cookies, headers, temp_data

    @staticmethod
    async def __is_valid_username(username: str) -> bool:
        pattern = r"^[A-Za-z\d_]{1,13}$"
        return bool(re.match(pattern, username))

    @staticmethod
    async def __is_valid_password(password: str) -> bool:
        pattern = r"^[A-Za-z\d_]+$"
        return bool(re.match(pattern, password))

    async def create_player(self, username: str, password: str, nickname: str = "") -> dict:
        """This function takes the username, password and nickname of the new user and crated it on the panel using
        the browse automation and returns True if user created otherwise False if we encounter any errors."""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Username must be 13 or fewer characters long and contain only letters,"
                           " numbers, and underscores.",
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
                'message': "Password must only contain letters, numbers, and underscores.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                    "nickname": nickname,
                    "score": 0
                }
            }
        cookies, headers, others = await self.__load_auth_data()
        agent_id = others['user']['agent_id']
        payloads = {
            'account': username,
            'nickname': nickname,
            'login_pwd': password,
            'check_pwd': password,
            'rechargeamount': "",
            'locale': others['il8n'],
            'timezone': others['time_zone'],
            '__cookie': cookies[f"__cookie{agent_id}"]
        }
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
                    response_text = await response.text()
                    json_data = json.loads(s=response_text)
                    if not json_data['code'] == 200:
                        await self.__logger.logs(
                            message=f"ERROR: Response is not correct and user not created: {response_text}",
                            function=inspect.currentframe().f_code.co_name
                        )
                        return {
                            'status': 422,
                            'message': "User not created. Please try again after few minutes.",
                            "data": {
                                "username": username,
                                "datetime": datetime.now(tz=UTC).__str__(),
                                "nickname": nickname,
                                "score": 0
                            }
                        }
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
        cookies, headers, others = await self.__load_auth_data()
        agent_id = others['user']['agent_id']
        payloads = {
            'agent_id': agent_id,
            'locale': others['il8n'],
            'timezone': others['time_zone'],
            '__cookie': cookies[f"__cookie{agent_id}"]
        }
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
                    cookies=cookies,
                    data=payloads
            ) as response:
                if response.status == 200:
                    response_text = await response.text()
                    json_data = json.loads(s=response_text)
                    if json_data['code'] == 200:
                        return {
                            'status': 200,
                            'message': "Successfully fetched panel scores.",
                            "data": {
                                "datetime": datetime.now(tz=UTC).__str__(),
                                'score': int(float(json_data['data']['t']))
                            }
                        }

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
                'message': "Password must only contain letters, numbers, and underscores.",
                "data": {
                    "username": username,
                    "newpassword": new_password,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        cookies, headers, others = await self.__load_auth_data()
        agent_id = others['user']['agent_id']
        payloads = {
            'limit': 20,
            'page': 1,
            'type': 1,
            'search': username,
            'locale': others['il8n'],
            'timezone': others['time_zone'],
            '__cookie': cookies[f"__cookie{agent_id}"]
        }
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.post(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    data=payloads
            ) as response:
                if response.status == 200:
                    response_text = await response.text()
                    json_data = json.loads(s=response_text)
                    for user in json_data['data']['list']:
                        if user['login_name'] == username:
                            user_id = user['user_id']
                            payloads = {
                                'login_pwd': new_password,
                                'check_pwd': new_password,
                                'uid': user_id,
                                'locale': others['il8n'],
                                'timezone': others['time_zone'],
                                '__cookie': cookies[f"__cookie{agent_id}"]
                            }
                            async with session.post(
                                    url=self.__RESET_PASSWORD_API,
                                    headers=headers,
                                    cookies=cookies,
                                    data=payloads
                            ) as reset_password_response:
                                if reset_password_response.status == 200:
                                    response_text = await reset_password_response.text()
                                    json_data = json.loads(s=response_text)
                                    if json_data['code'] == 200:
                                        return {
                                            'status': 200,
                                            'message': "Password reset successfully.",
                                            "data": {
                                                "username": username,
                                                "newpassword": new_password,
                                                "datetime": datetime.now(tz=UTC).__str__(),
                                            }
                                        }
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
        cookies, headers, others = await self.__load_auth_data()
        agent_id = others['user']['agent_id']
        payloads = {
            'limit': 20,
            'page': 1,
            'type': 1,
            'search': username,
            'locale': others['il8n'],
            'timezone': others['time_zone'],
            '__cookie': cookies[f"__cookie{agent_id}"]
        }
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.post(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    data=payloads
            ) as response:
                if response.status == 200:
                    response_text = await response.text()
                    json_data = json.loads(s=response_text)
                    for user in json_data['data']['list']:
                        if user['login_name'] == username:
                            user_id = user['user_id']
                            current_user_balance: int = int(user['balance'])
                            if current_user_balance >= score:
                                payloads = {
                                    'account': others['user']['login_name'],
                                    'amount': str(score),
                                    'balance': current_user_balance,
                                    'remark': '',
                                    'user_id': user_id,
                                    'type': 2,
                                    'locale': others['il8n'],
                                    'timezone': others['time_zone'],
                                    '__cookie': cookies[f"__cookie{agent_id}"]
                                }
                                async with session.post(
                                        url=self.__REDEEM_SCORE_API,
                                        headers=headers,
                                        cookies=cookies,
                                        data=payloads
                                ) as redeem_response:
                                    if redeem_response.status == 200:
                                        response_text = await redeem_response.text()
                                        json_data = json.loads(s=response_text)
                                        if json_data['code'] == 200:
                                            return {
                                                'status': 200,
                                                'message': "Score successfully redeemed scores from the game.",
                                                "data": {
                                                    "username": username,
                                                    "new_scores": int(json_data['data']['Balance']),
                                                    "datetime": datetime.now(tz=UTC).__str__(),
                                                }
                                            }
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
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "Invalid username.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        cookies, headers, others = await self.__load_auth_data()
        agent_id = others['user']['agent_id']
        payloads = {
            'limit': 20,
            'page': 1,
            'type': 1,
            'search': username,
            'locale': others['il8n'],
            'timezone': others['time_zone'],
            '__cookie': cookies[f"__cookie{agent_id}"]
        }
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.post(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    data=payloads
            ) as response:
                if response.status == 200:
                    response_text = await response.text()
                    json_data = json.loads(s=response_text)
                    for user in json_data['data']['list']:
                        if user['login_name'] == username:
                            current_user_balance: int = int(user['balance'])
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
        cookies, headers, others = await self.__load_auth_data()
        agent_id = others['user']['agent_id']
        payloads = {
            'limit': 20,
            'page': 1,
            'type': 1,
            'search': username,
            'locale': others['il8n'],
            'timezone': others['time_zone'],
            '__cookie': cookies[f"__cookie{agent_id}"]
        }
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                timeout=timeout
        ) as session:
            async with session.post(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    cookies=cookies,
                    data=payloads
            ) as response:
                if response.status == 200:
                    response_text = await response.text()
                    json_data = json.loads(s=response_text)
                    for user in json_data['data']['list']:
                        if user['login_name'] == username:
                            user_id = user['user_id']
                            current_user_balance: int = int(user['balance'])
                            payloads = {
                                'account': others['user']['login_name'],
                                'amount': str(score),
                                'balance': current_user_balance,
                                'remark': '',
                                'user_id': user_id,
                                'type': 1,
                                'locale': others['il8n'],
                                'timezone': others['time_zone'],
                                '__cookie': cookies[f"__cookie{agent_id}"]
                            }
                            async with session.post(
                                    url=self.__ADD_SCORE_API,
                                    headers=headers,
                                    cookies=cookies,
                                    data=payloads
                            ) as add_response:
                                if add_response.status == 200:
                                    response_text = await add_response.text()
                                    json_data = json.loads(s=response_text)
                                    if json_data['code'] == 200:
                                        return {
                                            'status': 200,
                                            'message': "Score successfully added to the game.",
                                            "data": {
                                                "username": username,
                                                "new_scores": int(json_data['data']['Balance']),
                                                "datetime": datetime.now(tz=UTC).__str__(),
                                            }
                                        }
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
