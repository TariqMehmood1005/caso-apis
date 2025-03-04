from colorama import Fore, Style, init
from functools import partial
import logging.handlers
import logging
import asyncio
import inspect
import os

# Initialize colorama
init(autoreset=True)


class AsyncLogger:
    def __init__(
            self,
            class_name: str,
            log_file: str = 'PanelsHandler/PanelLogs/panel_logs.log',
            when: str = 'midnight',
            interval: int = 1,
            backup_count: int = 7
    ):
        self.class_name = class_name
        self.logger = logging.getLogger(class_name)
        self.logger.setLevel(logging.DEBUG)

        # Format string for logs
        log_format_str = "%(asctime)s - %(levelname)s - %(class_name)s - %(func_name)s - %(message)s"

        # Console handler with color support
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self.ColoredFormatter(log_format_str))
        self.logger.addHandler(console_handler)

        # File handler
        self.__logs_file: str = log_file
        self.__create_dirs()
        file_handler = logging.handlers.TimedRotatingFileHandler(
            filename=self.__logs_file,
            when=when,
            interval=interval,
            backupCount=backup_count,
            encoding='utf-8',
            utc=False
        )
        file_handler.setFormatter(logging.Formatter(log_format_str, datefmt="%Y-%m-%d %H:%M:%S"))
        self.logger.addHandler(file_handler)

    class ColoredFormatter(logging.Formatter):
        """Custom formatter to apply colors based on log level."""
        LEVEL_COLORS = {
            logging.DEBUG: Fore.BLUE + Style.BRIGHT,
            logging.INFO: Fore.GREEN,
            logging.WARNING: Fore.YELLOW,
            logging.ERROR: Fore.RED + Style.BRIGHT
        }

        def format(self, record):
            log_message = super().format(record)
            color = self.LEVEL_COLORS.get(record.levelno, "")
            return f"{color}{log_message}{Style.RESET_ALL}"

    def __create_dirs(self):
        """Creates the directory for log files if it doesn't exist."""
        os.makedirs(name=os.path.dirname(self.__logs_file), exist_ok=True)

    async def logs(self, message: str, function: str = None):
        """
        Asynchronously logs a message with the specified function name.
        """
        if function is None:
            frame = inspect.currentframe().f_back
            function = frame.f_code.co_name if frame else 'N/A'
        level = logging.INFO
        if message.startswith("ERROR:"):
            level = logging.ERROR
        elif message.startswith("WARNING:"):
            level = logging.WARNING
        elif message.startswith("DEBUG:"):
            level = logging.DEBUG

        extra = {"func_name": function, "class_name": self.class_name}
        loop = asyncio.get_running_loop()
        log_func = partial(self.logger.log, level, message, extra=extra)
        await loop.run_in_executor(None, log_func)
