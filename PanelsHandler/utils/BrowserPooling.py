from playwright.async_api import (async_playwright, Page, TimeoutError, BrowserContext,
                                  Playwright, Browser, ElementHandle, ProxySettings)
from aiohttp import BasicAuth, ClientSession, ClientTimeout
from PanelsHandler.utils.randomuser import random_user_agents
from PanelsHandler.utils.CaptchaSolver import CaptchaSolver
from urllib.parse import urlparse
from datetime import datetime
from random import choice
from asyncio import sleep
import traceback
import json
import os
import re


class BrowserPool(object):
    __TEMP_CAPTCHA_PTH: str = os.path.abspath(path="TempFiles")

    def __init__(
            self,
            login_page_url: str,
            landing_page_url: str,
            num_browsers: int = 2,
            max_browsers: int = 10,
            storage_state_path: str = "PanelsHandler/PanelMemoryFiles/storage.json",
            trained_captcha_solver_model_path: str = "PanelsHandler/TrainedModels/captcha_solver_v1.keras",
            panel_username: str = "darkbytes",
            panel_password: str = "AbdulMoez@@5454",
            enable_js: bool = True,
            headless: bool = True,
            timeout: int = 30000,
            proxy: any([ProxySettings, None]) = None,
            captcha_max_length: int = 5,
            image_shape: tuple = (40, 120),
            captcha_solver_vocab: list = None
    ):
        self.__headless: bool = headless
        self.__login_page_url: str = login_page_url
        self.__landing_page_url: str = landing_page_url
        self.__storage_state_path: str = os.path.abspath(path=storage_state_path).__str__()
        self.__captcha_solver: CaptchaSolver = CaptchaSolver(
            captcha_model_path=trained_captcha_solver_model_path,
            max_length=captcha_max_length,
            image_shape=image_shape,
            vocab=captcha_solver_vocab
        )
        self.__enable_js: bool = enable_js
        self.__panel_username: str = panel_username
        self.__panel_password: str = panel_password
        self.__proxy: any([ProxySettings, None]) = proxy
        self.__timeout: int = timeout
        self.__create_dirs()
        # Browser hyperparameters
        self.pool: list[tuple[Playwright, Browser, Page]] = []
        self.busy_status: list[bool] = []
        self.num_browsers: int = num_browsers
        self.max_browsers: int = max_browsers

    def __create_dirs(self):
        """This function at start creates the temporary folder to store captcha images and makesure that
        our browser storage store folder is created as well"""
        os.makedirs(name=os.path.dirname(p=self.__storage_state_path), exist_ok=True)
        os.makedirs(name=os.path.dirname(p=self.__TEMP_CAPTCHA_PTH), exist_ok=True)

    async def get_proxy_details(self):
        """
        Extracts proxy URL and authentication details.
        :return: Tuple (proxy_url, proxy_auth) or (None, None) if no proxy is set.
        """
        if not self.__proxy:
            return None, None
        if not self.__proxy.get('server'):
            return None, None
        parsed_url = urlparse(self.__proxy['server'])
        proxy_host = parsed_url.hostname
        proxy_port = parsed_url.port
        if self.__proxy.get('username') and self.__proxy.get('password'):
            proxy_auth = BasicAuth(login=self.__proxy['username'], password=self.__proxy['password'])
            proxy_url = f"http://{self.__proxy['username']}:{self.__proxy['password']}@{proxy_host}:{proxy_port}"
        else:
            proxy_auth = None
            proxy_url = f"http://{proxy_host}:{proxy_port}"
        return proxy_url, proxy_auth

    async def ping_server(self, target_url: str) -> bool:
        """
        Asynchronously checks if the target server is reachable via an HTTP proxy with authentication.
        :param target_url: The hostname or IP address of the target server.
        :return: True if the server is reachable via the proxy, False otherwise.
        """
        try:
            base_proxy_url, base_proxy_auth = await self.get_proxy_details()
            timeout = self.__timeout if isinstance(
                self.__timeout, ClientTimeout
            ) else ClientTimeout(total=self.__timeout)
            async with ClientSession(timeout=timeout) as session:
                async with session.head(
                        url=target_url,
                        proxy=base_proxy_url,
                        auth=base_proxy_auth,
                        headers=await self._create_headers()
                ) as response:
                    if response.status < 400:
                        return True
                    else:
                        return False
        except Exception as e:
            _ = e
            return False

    @staticmethod
    async def _create_headers() -> dict:
        """
        This function will create the headers for headless browser as playwright headless browser creates issues
        with default parameters
        """
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": "",
            "Referer": "/",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": choice(random_user_agents),
        }

    async def __save_session(self, context: BrowserContext) -> None:
        """This functon is used for creating the session storage file, and it takes the context: BrowserContext
        of the current browser session to store the state of the browser for latter use."""
        await context.storage_state(path=self.__storage_state_path)

    async def __save_tokens(self, context: BrowserContext, token: str) -> None:
        cookies = await context.cookies()
        data = {
            "cookies": cookies,
            'auth_token': token
        }
        with open(self.__storage_state_path, "w") as file:
            json.dump(data, file, indent=4)

    async def create_session(self) -> bool:
        """This function logins the website and solve captcha using machine learning technique. After that
        it log in to the website and store its state which makes the other processes fast. it returns True
        if session created otherwise False"""
        while True:
            try:
                playwright_reference: Playwright = await async_playwright().start()
                browser: Browser = await playwright_reference.chromium.launch(
                    headless=self.__headless,
                    proxy=self.__proxy
                )
                context: BrowserContext = await browser.new_context(java_script_enabled=self.__enable_js)
                await context.set_extra_http_headers(headers=await self._create_headers())
                browser_page: Page = await context.new_page()
                await browser_page.goto(
                    url=self.__login_page_url,
                    wait_until="domcontentloaded",
                    timeout=self.__timeout
                )
                try:
                    while True:
                        try:
                            image_path: str = os.path.join(
                                self.__TEMP_CAPTCHA_PTH, datetime.now().strftime("%Y_%m_%d_%H%M%S")).__str__()
                            element: ElementHandle = await browser_page.query_selector(selector='img[id="ImageCheck"]')
                            await element.screenshot(path=image_path)
                            prediction_text: str = await self.__captcha_solver.predict_from_image_path(
                                image_path=image_path
                            )
                            print(f"Captcha Solution: {prediction_text}")
                            element: ElementHandle = await browser_page.query_selector(
                                selector='input[name="txtLoginName"]')
                            await element.fill(value=self.__panel_username)
                            element: ElementHandle = await browser_page.query_selector(
                                selector='input[name="txtLoginPass"]')
                            await element.fill(value=self.__panel_password)
                            element: ElementHandle = await browser_page.query_selector(
                                selector='input[name="txtVerifyCode"]')
                            await element.fill(value=prediction_text)
                            element: ElementHandle = await browser_page.query_selector(
                                selector='input[name="btnLogin"]')
                            await element.click()
                            try:
                                os.remove(path=image_path)
                            except Exception as e:
                                _ = e
                            if await browser_page.wait_for_selector(
                                    selector='input[id="mb_btn_ok"]',
                                    timeout=self.__timeout
                            ):
                                element: ElementHandle = await browser_page.query_selector(
                                    selector='input[id="mb_btn_ok"]')
                                await element.click()
                                print("Retrying Captcha..")
                                continue
                        except (AttributeError, TimeoutError):
                            await browser_page.wait_for_load_state(
                                state='domcontentloaded',
                                timeout=self.__timeout)
                            break
                    await self.__save_session(context=context)
                    await browser.close()
                    await playwright_reference.stop()
                    return True
                except Exception as e:
                    full_error = f"ERROR: {traceback.format_exc()}\n{e}"
                    print(full_error)
                    await browser.close()
                    await playwright_reference.stop()
                    continue  # Retry
            except Exception as e:
                print(f"Exception while creating session: {e}")
                continue  # Retry

    async def __game_vault_cookies(self,
                                   context: BrowserContext,
                                   token: str,
                                   user: dict,
                                   time_zone: str,
                                   il8n: str
                                   ) -> None:
        cookies = await context.cookies()
        data = {
            "cookies": cookies,
            'token': token,
            'user': user,
            'time_zone': time_zone,
            'il8n': il8n
        }
        with open(file=self.__storage_state_path, mode="w") as file:
            json.dump(data, file, indent=4)

    async def game_vault_related_session(
            self,
            username_place_holder: str = 'username',
            password_place_holder: str = 'password',
            is_juwa_panel: bool = False
    ):
        """This function logins the website and solve captcha using machine learning technique. After that
                it log in to the website and store its state which makes the other processes fast. it returns True
                if session created otherwise False"""
        while True:
            try:
                playwright_reference: Playwright = await async_playwright().start()
                browser: Browser = await playwright_reference.chromium.launch(
                    headless=self.__headless,
                    proxy=self.__proxy
                )
                context: BrowserContext = await browser.new_context(java_script_enabled=self.__enable_js)
                await context.set_extra_http_headers(headers=await self._create_headers())
                browser_page: Page = await context.new_page()
                await browser_page.goto(
                    url=self.__login_page_url,
                    wait_until="domcontentloaded",
                    timeout=self.__timeout
                )
                try:
                    while True:
                        try:
                            image_path: str = os.path.join(
                                self.__TEMP_CAPTCHA_PTH, datetime.now().strftime("%Y_%m_%d_%H%M%S")).__str__()
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='img[class="imgCode"]', timeout=self.__timeout
                            )
                            await element.screenshot(path=image_path)
                            prediction_text: str = await self.__captcha_solver.predict_from_image_path(
                                image_path=image_path
                            )
                            print(f"Captcha Solution: {prediction_text}")
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector=f'input[placeholder="{username_place_holder}" i]', timeout=self.__timeout
                            )
                            await element.fill(value=self.__panel_username)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector=f'input[placeholder="{password_place_holder}" i]', timeout=self.__timeout
                            )
                            await element.fill(value=self.__panel_password)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='div[class*="loginCode"] > input', timeout=self.__timeout
                            )
                            await element.fill(value=prediction_text)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='label[class*="remember"]', timeout=self.__timeout
                            )
                            if 'is-checked' not in await element.get_attribute(name='class'):
                                element: ElementHandle = await browser_page.wait_for_selector(
                                    selector='label[class*="remember"]', timeout=self.__timeout
                                )
                                await element.click()
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='div[class*="login-btn"]  button', timeout=self.__timeout
                            )
                            await sleep(1.2)
                            await element.click()
                            try:
                                os.remove(path=image_path)
                            except Exception as e:
                                _ = e
                            await browser_page.wait_for_url(
                                url=self.__landing_page_url,
                                timeout=self.__timeout,
                                wait_until="domcontentloaded"
                            )
                            break
                        except (AttributeError, TimeoutError):
                            await browser_page.reload(
                                wait_until="domcontentloaded",
                                timeout=self.__timeout
                            )
                            print("Retrying Captcha..")
                            continue
                    if is_juwa_panel:
                        await sleep(delay=1.56)
                        token = json.loads(
                            s=await browser_page.evaluate(expression="window.sessionStorage.getItem('token')"))
                        user = json.loads(await browser_page.evaluate(
                            expression="window.sessionStorage.getItem('user')"))
                        time_zone = "cst"
                        il8n = await browser_page.evaluate(expression="window.sessionStorage.getItem('i18n')")
                        if not il8n:
                            il8n = "en-US"
                        else:
                            il8n = json.loads(il8n) if isinstance(il8n, str) else "en"
                    else:
                        token = await browser_page.evaluate(expression="window.localStorage.getItem('token')")
                        user = json.loads(await browser_page.evaluate(expression="window.localStorage.getItem('user')"))
                        time_zone = await browser_page.evaluate(expression="window.localStorage.getItem('timezone')")
                        il8n = await browser_page.evaluate(expression="window.localStorage.getItem('i18n')")
                    await self.__game_vault_cookies(
                        context=context,
                        token=token,
                        user=user,
                        time_zone=time_zone,
                        il8n=il8n
                    )
                    await browser.close()
                    await playwright_reference.stop()
                    return True
                except Exception as e:
                    full_error = f"ERROR: {traceback.format_exc()}\n{e}"
                    print(full_error)
                    await browser.close()
                    await playwright_reference.stop()
                    continue  # Retry
            except Exception as e:
                print(f"Exception while creating session: {e}")
                continue  # Retry

    async def game_room_related_session(self) -> bool:
        """This function logins the website and solve captcha using machine learning technique. After that
        it log in to the website and store its state which makes the other processes fast. it returns True
        if session created otherwise False"""
        while True:
            try:
                playwright_reference: Playwright = await async_playwright().start()
                browser: Browser = await playwright_reference.chromium.launch(
                    headless=self.__headless,
                    proxy=self.__proxy
                )
                context: BrowserContext = await browser.new_context(java_script_enabled=self.__enable_js)
                await context.set_extra_http_headers(headers=await self._create_headers())
                browser_page: Page = await context.new_page()
                await browser_page.goto(
                    url=self.__login_page_url,
                    wait_until="domcontentloaded",
                    timeout=self.__timeout
                )
                try:
                    while True:
                        try:
                            image_path: str = os.path.join(
                                self.__TEMP_CAPTCHA_PTH, datetime.now().strftime("%Y_%m_%d_%H%M%S")).__str__()
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='canvas[id="verifyCanvas"]', timeout=self.__timeout
                            )
                            await element.screenshot(path=image_path)
                            prediction_text: str = await self.__captcha_solver.predict_from_image_path(
                                image_path=image_path
                            )
                            print(f"Captcha Solution: {prediction_text}")
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='input[name="username"]', timeout=self.__timeout
                            )
                            await element.fill(value=self.__panel_username)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='input[name="password"]', timeout=self.__timeout
                            )
                            await element.fill(value=self.__panel_password)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='input[name="captcha"]', timeout=self.__timeout
                            )
                            await element.fill(value=prediction_text)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='button[lay-filter="login"]', timeout=self.__timeout
                            )
                            await element.click()
                            try:
                                os.remove(path=image_path)
                            except Exception as e:
                                _ = e
                            await browser_page.wait_for_url(
                                url=self.__landing_page_url,
                                timeout=self.__timeout
                            )
                            break
                        except (AttributeError, TimeoutError):
                            try:
                                element: ElementHandle = await browser_page.wait_for_selector(
                                    selector='canvas[id="verifyCanvas"]', timeout=self.__timeout
                                )
                                await element.click()
                            except TimeoutError:
                                token: str = await browser_page.evaluate(
                                    expression="window.sessionStorage.getItem('token')")
                                if token:
                                    await self.__save_tokens(context=context, token=token)
                                    await browser.close()
                                    await playwright_reference.stop()
                                    return True
                                print("Retrying Captcha..")
                                continue
                            continue
                    token: str = await browser_page.evaluate(expression="window.sessionStorage.getItem('token')")
                    await self.__save_tokens(context=context, token=token)
                    await browser.close()
                    await playwright_reference.stop()
                    return True
                except Exception as e:
                    full_error = f"ERROR: {traceback.format_exc()}\n{e}"
                    print(full_error)
                    await browser.close()
                    await playwright_reference.stop()
                    continue  # Retry
            except Exception as e:
                print(f"Exception while creating session: {e}")
                continue  # Retry

    async def __agent_yolo_cookies(self, context: BrowserContext, token: str) -> None:
        cookies = await context.cookies()
        data = {
            "cookies": cookies,
            'token': token
        }
        with open(self.__storage_state_path, "w") as file:
            json.dump(data, file, indent=4)

    async def agent_yolo_related_session(self, no_captcha: bool = False) -> bool:
        """This function logins the website and solve captcha using machine learning technique. After that
        it log in to the website and store its state which makes the other processes fast. it returns True
        if session created otherwise False"""
        while True:
            try:
                playwright_reference: Playwright = await async_playwright().start()
                browser: Browser = await playwright_reference.chromium.launch(
                    headless=self.__headless,
                    proxy=self.__proxy
                )
                context: BrowserContext = await browser.new_context(java_script_enabled=self.__enable_js)
                await context.set_extra_http_headers(headers=await self._create_headers())
                browser_page: Page = await context.new_page()
                await browser_page.goto(
                    url=self.__login_page_url,
                    wait_until="domcontentloaded",
                    timeout=self.__timeout
                )
                try:
                    while True:
                        try:
                            if not no_captcha:
                                image_path: str = os.path.join(
                                    self.__TEMP_CAPTCHA_PTH, datetime.now().strftime("%Y_%m_%d_%H%M%S")).__str__()
                                element: ElementHandle = await browser_page.wait_for_selector(
                                    selector='img[id="captcha"]', timeout=self.__timeout
                                )
                                await element.screenshot(path=image_path)
                                prediction_text: str = await self.__captcha_solver.predict_from_image_path(
                                    image_path=image_path
                                )
                                print(f"Captcha Solution: {prediction_text}")
                                element: ElementHandle = await browser_page.wait_for_selector(
                                    selector='input[name="captcha"]', timeout=self.__timeout
                                )
                                await element.fill(value=prediction_text)
                                try:
                                    os.remove(path=image_path)
                                except Exception as e:
                                    _ = e
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='input[name="username"]', timeout=self.__timeout
                            )
                            await element.fill(value=self.__panel_username)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='input[name="password"]', timeout=self.__timeout
                            )
                            await element.fill(value=self.__panel_password)
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='input[name="remember"]', timeout=self.__timeout
                            )
                            await element.click()
                            element: ElementHandle = await browser_page.wait_for_selector(
                                selector='button[class$="login-btn"]', timeout=self.__timeout
                            )
                            await element.click()
                            await browser_page.wait_for_url(
                                url=self.__landing_page_url,
                                timeout=self.__timeout
                            )
                            break
                        except (AttributeError, TimeoutError):
                            print("Retrying Captcha..")
                            continue
                    token_match: any([re.Match[str], None]) = re.search(
                        r'"token":"(.*?)"', await browser_page.content())
                    if not token_match:
                        return False
                    token: str = token_match.group(1).strip()
                    await self.__agent_yolo_cookies(context=context, token=token)
                    await browser.close()
                    await playwright_reference.stop()
                    return True
                except Exception as e:
                    full_error = f"ERROR: {traceback.format_exc()}\n{e}"
                    print(full_error)
                    await browser.close()
                    await playwright_reference.stop()
                    continue  # Retry
            except Exception as e:
                print(f"Exception while creating session: {e}")
                continue  # Retry

    async def create_browser(self) -> any([None, tuple[Playwright, Browser, Page]]):
        """
        This function will create the playwright browser and goto the url of landing page, and first it will check if
        the storage file is created or not if not created then this function first create the session file and then
        create the browser using that session file
        :return: None if the session is not able to create. If session created then it will return tuple of following
        order (Playwright, Browser, Page). We can handle the browser using these references
        """
        while True:
            try:
                if not os.path.isfile(path=self.__storage_state_path):
                    if not await self.create_session():
                        return None
                playwright_reference: Playwright = await async_playwright().start()
                browser: Browser = await playwright_reference.chromium.launch(
                    headless=self.__headless,
                    proxy=self.__proxy
                )
                context: BrowserContext = await browser.new_context(
                    java_script_enabled=self.__enable_js,
                    storage_state=self.__storage_state_path
                )
                await context.set_extra_http_headers(headers=await self._create_headers())
                browser_page: Page = await context.new_page()
                await browser_page.goto(
                    url=self.__landing_page_url,
                    wait_until="domcontentloaded",
                    timeout=self.__timeout
                )
                if self.__landing_page_url != browser_page.url:
                    print("Session Expired creating a new one")
                    await browser.close()
                    await playwright_reference.stop()
                    if not await self.create_session():
                        return None
                    continue  # Retry
                return playwright_reference, browser, browser_page
            except Exception as e:
                print(f"Exception while creating the browser: {e}")
                continue  # Retry

    async def create_ultra_panda_related_browser(self):
        while True:
            try:
                playwright_reference: Playwright = await async_playwright().start()
                browser: Browser = await playwright_reference.chromium.launch(
                    headless=self.__headless,
                    proxy=self.__proxy
                )
                context: BrowserContext = await browser.new_context(
                    java_script_enabled=self.__enable_js
                )
                await context.set_extra_http_headers(headers=await self._create_headers())
                browser_page: Page = await context.new_page()
                await browser_page.goto(
                    url=self.__login_page_url,
                    wait_until="domcontentloaded",
                    timeout=self.__timeout
                )
                login_username: ElementHandle = await browser_page.wait_for_selector(
                    selector='input[name="userName"]', timeout=self.__timeout
                )
                await login_username.fill(value=self.__panel_username)
                login_password: ElementHandle = await browser_page.wait_for_selector(
                    selector='input[name="passWd"]', timeout=self.__timeout
                )
                await login_password.fill(value=self.__panel_password)
                submit_button: ElementHandle = await browser_page.wait_for_selector(
                    selector='button[type="button"]', timeout=self.__timeout
                )
                await submit_button.click()
                await browser_page.wait_for_url(url=self.__landing_page_url, timeout=self.__timeout)
                return playwright_reference, browser, browser_page
            except Exception as e:
                print(f"Exception while creating the browser: {e}")
                continue  # Retry

    async def initialize_pool(self, ultra_panda_related: bool = False) -> bool:
        for _ in range(self.num_browsers):
            if ultra_panda_related:
                response = await self.create_ultra_panda_related_browser()
            else:
                response = await self.create_browser()
            if not response:
                continue
            playwright_reference: Playwright = response[0]
            browser: Browser = response[1]
            browser_page: Page = response[2]
            self.pool.append((playwright_reference, browser, browser_page))
            self.busy_status.append(False)
        return True

    async def get_available_browser(
            self,
            ultra_panda_related: bool = False
    ) -> any([tuple[None, None], tuple[tuple[Playwright, Browser, Page], int]]):
        """
        Retrieves an available browser from the pool. If all browsers are busy and the pool has reached
        the maximum size, waits until a browser becomes available or a timeout of 1 minute is reached.

        :param ultra_panda_related: Flag to indicate if an ultra panda related browser is needed.
        :return: A tuple containing the browser and its index, or (None, None) if no browser is available.
        """
        for i, busy in enumerate(self.busy_status):
            if not busy:
                self.busy_status[i] = True
                print(f"Browser at index {i} is now busy.")
                return self.pool[i], i

        # If pool size is less than max_browsers, attempt to create a new browser
        if len(self.pool) < self.max_browsers:
            print("No available browser found. Attempting to create a new one.")
            if ultra_panda_related:
                response = await self.create_ultra_panda_related_browser()
            else:
                response = await self.create_browser()
            if not response:
                print("Failed to create a new browser.")
                return None, None
            playwright_reference: Playwright = response[0]
            browser: Browser = response[1]
            browser_page: Page = response[2]
            self.pool.append((playwright_reference, browser, browser_page))
            self.busy_status.append(True)  # Mark the new browser as busy
            print(f"New browser created and added to pool at index {len(self.pool) - 1}.")
            return self.pool[-1], len(self.pool) - 1
        print("Maximum browsers reached. Waiting for a browser to become available.")
        timeout_in_minutes = 2
        timeout = timeout_in_minutes * 60  # seconds
        interval = 1  # seconds
        elapsed = 0
        while elapsed < timeout:
            for i, busy in enumerate(self.busy_status):
                if not busy:
                    self.busy_status[i] = True
                    return self.pool[i], i
            await sleep(interval)
            elapsed += interval
        print("Timeout reached. No browser available.")
        return None, None

    async def release_browser(self, index) -> None:
        self.busy_status[index] = False

    async def destroy_pool(self) -> None:
        for pool_index in range(len(self.pool)):
            try:
                await self.pool[pool_index][1].close()
                await self.pool[pool_index][0].stop()
            except Exception as e:
                print(f"Error while closing pool at index {pool_index}: {e}")
        self.busy_status.clear()
        self.pool.clear()

    async def update_pool(self, ultra_panda_related: bool = False):
        for pool_index in range(len(self.pool)):
            while True:
                if self.busy_status[pool_index]:
                    await sleep(2)
                else:
                    break
            try:
                await self.pool[pool_index][1].close()
                await self.pool[pool_index][0].stop()
            except Exception as e:
                print(f"Error while closing pool at index {pool_index}: {e}")
        self.busy_status.clear()
        self.pool.clear()
        await self.initialize_pool(ultra_panda_related=ultra_panda_related)
