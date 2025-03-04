from asyncio import sleep, new_event_loop, set_event_loop
from playwright.async_api import ProxySettings
from PanelsHandler.utils.BrowserPooling import BrowserPool
from PanelsHandler.utils.logger import AsyncLogger
from datetime import datetime, UTC
from aiohttp import ClientTimeout
from bs4 import BeautifulSoup
from yarl import URL
import aiofiles
import threading
import aiohttp
import inspect
import json
import os
import re


class AgentYoloPanel(object):
    """Unofficial API wrapper for the Agent Yolo panel handles the API calls and responses"""
    __LOGIN_URL: str = "https://agent.yolo777.game/admin/auth/login"
    __LANDING_PAGE: str = "https://agent.yolo777.game/admin"
    __PANEL_SCORE_API: str = "https://agent.yolo777.game/admin/refresh_score"
    __ADD_PLAYER_API: str = "https://agent.yolo777.game/admin/player_list"
    __USER_SCORE_API: str = "https://agent.yolo777.game/admin/player_list"
    __ADD_SCORE_API: str = "https://agent.yolo777.game/admin/dcat-api/form"
    __REDEEM_SCORE_API: str = "https://agent.yolo777.game/admin/dcat-api/form"
    __RESET_PASSWORD_API: str = "https://agent.yolo777.game/admin/dcat-api/form"

    def __init__(
            self,
            headless: bool = True,
            storage_state_path: str = "PanelsHandler/PanelMemoryFiles/agent_yolo_storage.json",
            trained_captcha_solver_model_path: str = "PanelsHandler/TrainedModels/captcha_solver_agent_yolo_0.1.keras",
            logs_file: str = "PanelsHandler/PanelLogs/agent_yolo_logs.log",
            logs_backup_count: int = 7,
            panel_username: str = "Darkbytes02",
            panel_password: str = "AbdulMoez784",
            enable_js: bool = True,
            timeout: int = 40000,
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
        if not await self.browser_pool.agent_yolo_related_session():
            await self.__logger.logs(
                message="ERROR: Agent Yolo session does not created.",
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

    async def ping_game_server(self) -> dict:
        return {
            "status": "active" if await self.browser_pool.ping_server(target_url=self.__LOGIN_URL) else "inactive",
            "pinged_url": self.__LOGIN_URL,
            "datetime": datetime.now(tz=UTC).__str__(),
        }

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
                await self.browser_pool.agent_yolo_related_session()
            except Exception as e:
                print(f"Error: {str(e)}")

    async def __update_cookies(self, response: aiohttp.ClientResponse, csrf_token: str) -> None:
        """
        Asynchronously updates the cookie history by extracting cookies from the response
        and saving them along with the CSRF token to a JSON file.

        :param response: The aiohttp ClientResponse object containing cookies.
        :param csrf_token: The CSRF token to be saved.
        """
        cookies = []
        for cookie in response.cookies.values():
            cookie_dict = {
                "name": cookie.key,
                "value": cookie.value,
                "domain": cookie["domain"] if "domain" in cookie else "",
                "path": cookie["path"] if "path" in cookie else "/",
                "secure": cookie["secure"] if "secure" in cookie else False,
                "expires": cookie["expires"] if "expires" in cookie else None,
                "httponly": cookie["httponly"] if "httponly" in cookie else False,
                "samesite": cookie["samesite"] if "samesite" in cookie else "Lax"
            }
            cookies.append(cookie_dict)
        raw_cookies = {
            "cookies": cookies,
            "token": csrf_token
        }
        async with aiofiles.open(self.__storage_state_path, "w") as file:
            await file.write(json.dumps(raw_cookies, indent=4))

    async def __load_cookies(self) -> tuple[aiohttp.CookieJar, dict[str, str]]:
        """
        Asynchronously loads cookies and CSRF token from a JSON file and reconstructs
        the aiohttp CookieJar and necessary headers.

        :return: A tuple containing the CookieJar and headers dictionary.
        """
        while not os.path.exists(self.__storage_state_path):
            await self.stop_scheduler_function()
            await self.initialize_panel()
        try:
            async with aiofiles.open(file=self.__storage_state_path, mode="r") as file:
                content = await file.read()
                data = json.loads(content)
            if not isinstance(data.get("cookies"), list):
                await self.__logger.logs(
                    message="ERROR: Invalid 'cookies' format in JSON. Expected a list.",
                    function=inspect.currentframe().f_code.co_name
                )
                return aiohttp.CookieJar(), {}
            jar = aiohttp.CookieJar()
            for cookie in data["cookies"]:
                if not isinstance(cookie, dict):
                    await self.__logger.logs(
                        message=f"ERROR: Invalid cookie entry (not a dict): {cookie}",
                        function=inspect.currentframe().f_code.co_name
                    )
                    continue
                name = cookie.get('name')
                value = cookie.get('value')
                domain = cookie.get('domain')
                path = cookie.get('path', '/')
                if not name or not value or not domain:
                    await self.__logger.logs(
                        message=f"ERROR: Missing required cookie attributes: {cookie}",
                        function=inspect.currentframe().f_code.co_name
                    )
                    continue
                try:
                    response_url = URL.build(scheme='https', host=domain, path=path)
                except Exception as e:
                    await self.__logger.logs(
                        message=f"ERROR: Error constructing URL for cookie '{name}': {e}",
                        function=inspect.currentframe().f_code.co_name
                    )
                    continue
                jar.update_cookies({name: value}, response_url=response_url)
            browser_headers = {
                "x-csrf-token": data.get("token", ""),
                "x-requested-with": "XMLHttpRequest"
            }
            return jar, browser_headers
        except (json.JSONDecodeError, KeyError) as e:
            await self.__logger.logs(
                message=f"ERROR: Error loading cookies: {e}",
                function=inspect.currentframe().f_code.co_name
            )
            return aiohttp.CookieJar(), {}
        except Exception as e:
            await self.__logger.logs(
                message=f"ERROR: Unexpected error: {e}",
                function=inspect.currentframe().f_code.co_name
            )
            return aiohttp.CookieJar(), {}

    @staticmethod
    async def __is_valid_username(username: str) -> bool:
        pattern = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d_]{6,24}$"
        return bool(re.match(pattern, username))

    @staticmethod
    async def __validate_nickname(nickname: str) -> bool:
        """
        Validates that the nickname length is between 6 and 15 characters.

        Args:
            nickname (str): The nickname to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        if 6 <= len(nickname) <= 15:
            return True
        return False

    @staticmethod
    async def __is_valid_password(password: str) -> bool:
        """
        Validates that the password length is between 6 and 24 characters.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        if 6 <= len(password) <= 24:
            return True
        return False

    async def create_player(self, username: str, password: str, nickname: str = "") -> dict:
        """This function takes the username, password and nickname of the new user and crates it on the panel using
        the browse automation and returns True if user created otherwise False if we encounter any errors."""
        if not await self.__is_valid_username(username=username):
            return {
                'status': 400,
                'message': "The username must contain numbers and letters and be between 6 and 24 characters long.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                    "nickname": nickname,
                    "score": 0
                }
            }
        if nickname and not await self.__validate_nickname(nickname=nickname):
            return {
                'status': 400,
                'message': "Nickname length must be between 6-15 characters.",
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
                'message': "Password length must be between 6-24 characters.",
                "data": {
                    "username": username,
                    "datetime": datetime.now(tz=UTC).__str__(),
                    "nickname": nickname,
                    "score": 0
                }
            }
        cookies, headers = await self.__load_cookies()
        payloads = {
            "Accounts": username,
            "NickName": nickname,
            "Recharge_Amount": 0,
            "LogonPass": password,
            "ChannelID": "",
            "RegAccounts": "",
            "AgentID": "",
            "InsurePass": "",
            "FaceID": "",
            "LastLogonIP": "0.0.0.0",
            "RegisterIP": "0.0.0.0",
            "MemberOrder": "",
            "MemberExp": "",
            "RegisterMobile": "",
            "RegisterMachine": "",
            "BindAgentDate": "",
            "Nullity": 1,
            "_previous_": "https://agent.yolo777.game/admin/player_list",
            "_token": headers['x-csrf-token'],

        }
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                cookie_jar=cookies,
                timeout=timeout
        ) as session:
            async with session.post(
                    url=self.__ADD_PLAYER_API,
                    headers=headers,
                    data=payloads
            ) as response:
                if response.status == 200:
                    temp_response = await response.json()
                    if not temp_response['status']:
                        await self.__logger.logs(
                            message=f"ERROR: Response is not correct and user not created: {temp_response}",
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
                    await self.__update_cookies(response=response, csrf_token=headers['x-csrf-token'])
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
        cookies, headers = await self.__load_cookies()
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                cookie_jar=cookies,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__PANEL_SCORE_API,
                    headers=headers
            ) as response:
                if response.status == 200:
                    panel_score = await response.text()
                    await self.__update_cookies(response=response, csrf_token=headers['x-csrf-token'])
                    return {
                        'status': 200,
                        'message': "Successfully fetched panel scores.",
                        "data": {
                            "datetime": datetime.now(tz=UTC).__str__(),
                            'score': int(float(panel_score.strip()))
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
                'message': "Password length must be between 6-24 characters.",
                "data": {
                    "username": username,
                    "newpassword": new_password,
                    "datetime": datetime.now(tz=UTC).__str__(),
                }
            }
        cookies, headers = await self.__load_cookies()
        parameters = {
            "Accounts": username,
            "NickName": "",
            "RegisterDate[start]": "",
            "RegisterDate[end]": "",
            "game_status": "",
            "UserID": "",
            '_pjax': "#pjax-container"
        }
        headers['x-pjax'] = 'true'
        headers['x-pjax-container'] = '#pjax-container'
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                cookie_jar=cookies,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    params=parameters
            ) as response:
                if response.status == 200:
                    await self.__update_cookies(response=response, csrf_token=headers['x-csrf-token'])
                    response_soup = BeautifulSoup(
                        markup=await response.content.read(),
                        features='html.parser'
                    )
                    table_id = response_soup.select(selector='table[id="grid-table"] > tbody tr')
                    for table_row in table_id:
                        try:
                            if table_row.select(selector='td > a')[1].get(key='data-content').strip() == username:
                                player_id = table_row.select(selector='td > a')[0].get(key='data-content').strip()
                                cookies, headers = await self.__load_cookies()
                                payloads = {
                                    "password": new_password,
                                    "_form_": r"App\Admin\Actions\ResetUserPass",
                                    "_current_": "https://agent.yolo777.game/admin/player_list?",
                                    "_payload_": json.dumps({
                                        "_current_": "https://agent.yolo777.game/admin/player_list?",
                                        "userid": player_id,
                                        "username": username,
                                        "renderable": "App_Admin_Actions_ResetUserPass",
                                        "_trans_": "user"
                                    }),
                                    "_token": headers['x-csrf-token']
                                }
                                async with session.post(
                                        url=self.__RESET_PASSWORD_API,
                                        headers=headers,
                                        data=payloads
                                ) as reset_password_response:
                                    await self.__update_cookies(
                                        response=reset_password_response,
                                        csrf_token=headers['x-csrf-token'])
                                    temp_response = await reset_password_response.json()
                                    if reset_password_response.status == 200 and temp_response['status'] == True:
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
                        except IndexError:
                            await self.__logger.logs(
                                message="DEBUG: Unable to find user",
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
        cookies, headers = await self.__load_cookies()
        parameters = {
            "Accounts": username,
            "NickName": "",
            "RegisterDate[start]": "",
            "RegisterDate[end]": "",
            "game_status": "",
            "UserID": "",
            '_pjax': "#pjax-container"
        }
        headers['x-pjax'] = 'true'
        headers['x-pjax-container'] = '#pjax-container'
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                cookie_jar=cookies,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    params=parameters
            ) as response:
                if response.status == 200:
                    await self.__update_cookies(response=response, csrf_token=headers['x-csrf-token'])
                    response_soup = BeautifulSoup(
                        markup=await response.content.read(),
                        features='html.parser'
                    )
                    table_id = response_soup.select(selector='table[id="grid-table"] > tbody tr')
                    for table_row in table_id:
                        try:
                            if table_row.select(selector='td > a')[1].get(key='data-content').strip() == username:
                                player_items = table_row.select(selector='td')
                                current_user_balance = player_items[5].text.strip()
                                player_id = table_row.select(selector='td > a')[0].get(key='data-content').strip()
                                if int(current_user_balance) >= score:
                                    cookies, headers = await self.__load_cookies()
                                    payloads = {
                                        "type": "2",
                                        "input_score": score,
                                        "remark": "",
                                        "_form_": r"App\Admin\Actions\UserRecharge",
                                        "_current_": "https://agent.yolo777.game/admin/player_list?",
                                        "_payload_": json.dumps({
                                            "_current_": "https://agent.yolo777.game/admin/player_list?",
                                            "UserID": player_id,
                                            "Accounts": username,
                                            "Score": current_user_balance,
                                            "type": "2",
                                            "renderable": "App_Admin_Actions_UserRecharge",
                                            "_trans_": "user"
                                        }),
                                        "_token": headers['x-csrf-token']
                                    }
                                    async with session.post(
                                            url=self.__REDEEM_SCORE_API,
                                            headers=headers,
                                            data=payloads
                                    ) as redeem_response:
                                        temp_response = await redeem_response.json()
                                        if redeem_response.status == 200 and temp_response['status'] == True:
                                            await self.__update_cookies(response=response,
                                                                        csrf_token=headers['x-csrf-token'])
                                            return {
                                                'status': 200,
                                                'message': "Score successfully redeemed scores from the game.",
                                                "data": {
                                                    "username": username,
                                                    "new_scores": int(current_user_balance) - score,
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
                        except IndexError:
                            await self.__logger.logs(
                                message="DEBUG: Unable to find user",
                                function=inspect.currentframe().f_code.co_name
                            )
                            return {
                                'status': 422,
                                'message': "Unable to find user. Please create a user first.",
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
        cookies, headers = await self.__load_cookies()
        parameters = {
            "Accounts": username,
            "NickName": "",
            "RegisterDate[start]": "",
            "RegisterDate[end]": "",
            "game_status": "",
            "UserID": "",
            '_pjax': "#pjax-container"
        }
        headers['x-pjax'] = 'true'
        headers['x-pjax-container'] = '#pjax-container'
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                cookie_jar=cookies,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    params=parameters
            ) as response:
                if response.status == 200:
                    await self.__update_cookies(response=response, csrf_token=headers['x-csrf-token'])
                    response_soup = BeautifulSoup(
                        markup=await response.content.read(),
                        features='html.parser'
                    )
                    table_id = response_soup.select(selector='table[id="grid-table"] > tbody tr')
                    for table_row in table_id:
                        try:
                            if table_row.select(selector='td > a')[1].get(key='data-content').strip() == username:
                                player_items = table_row.select(selector='td')
                                current_user_balance = player_items[5].text.strip()
                                return {
                                    'status': 200,
                                    'message': "Score successfully fetch from the game.",
                                    "data": {
                                        "username": username,
                                        "score": int(current_user_balance),
                                        "datetime": datetime.now(tz=UTC).__str__(),
                                    }
                                }
                        except IndexError:
                            await self.__logger.logs(
                                message="DEBUG: Unable to find user",
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
        cookies, headers = await self.__load_cookies()
        parameters = {
            "Accounts": username,
            "NickName": "",
            "RegisterDate[start]": "",
            "RegisterDate[end]": "",
            "game_status": "",
            "UserID": "",
            '_pjax': "#pjax-container"
        }
        headers['x-pjax'] = 'true'
        headers['x-pjax-container'] = '#pjax-container'
        base_proxy_url, base_proxy_auth = await self.browser_pool.get_proxy_details()
        timeout = self.__timeout if isinstance(self.__timeout, ClientTimeout) else ClientTimeout(total=self.__timeout)
        async with aiohttp.ClientSession(
                proxy=base_proxy_url,
                proxy_auth=base_proxy_auth,
                cookie_jar=cookies,
                timeout=timeout
        ) as session:
            async with session.get(
                    url=self.__USER_SCORE_API,
                    headers=headers,
                    params=parameters
            ) as response:
                if response.status == 200:
                    await self.__update_cookies(response=response, csrf_token=headers['x-csrf-token'])
                    response_soup = BeautifulSoup(
                        markup=await response.content.read(),
                        features='html.parser'
                    )
                    table_id = response_soup.select(selector='table[id="grid-table"] > tbody tr')
                    for table_row in table_id:
                        try:
                            if table_row.select(selector='td > a')[1].get(key='data-content').strip() == username:
                                player_items = table_row.select(selector='td')
                                current_user_balance = player_items[5].text.strip()
                                player_id = table_row.select(selector='td > a')[0].get(key='data-content').strip()
                                cookies, headers = await self.__load_cookies()
                                payloads = {
                                    "type": "1",
                                    "input_score": score,
                                    "remark": "",
                                    "_form_": r"App\Admin\Actions\UserRecharge",
                                    "_current_": "https://agent.yolo777.game/admin/player_list?",
                                    "_payload_": json.dumps({
                                        "_current_": "https://agent.yolo777.game/admin/player_list?",
                                        "UserID": player_id,
                                        "Accounts": username,
                                        "Score": current_user_balance,
                                        "type": "1",
                                        "renderable": "App_Admin_Actions_UserRecharge",
                                        "_trans_": "user"
                                    }),
                                    "_token": headers['x-csrf-token']
                                }
                                async with session.post(
                                        url=self.__ADD_SCORE_API,
                                        headers=headers,
                                        data=payloads
                                ) as add_response:
                                    temp_response = await add_response.json()
                                    if add_response.status == 200 and temp_response['status'] == True:
                                        await self.__update_cookies(response=response,
                                                                    csrf_token=headers['x-csrf-token'])
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
                        except IndexError:
                            await self.__logger.logs(
                                message="DEBUG: Unable to find user",
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

