"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

import logging.config
import os
from datetime import datetime

LOGGING_DIR = os.path.dirname(os.path.abspath(__file__))
LOGGER_CONF_PATH = os.path.join(LOGGING_DIR, "logging.conf")


def print_logging_settings():
    logger = logging.getLogger()
    print(f"Logger name: {logger.name}")
    print(f"Logger level: {logging.getLevelName(logger.level)}")

    for handler in logger.handlers:
        print(f"\nHandler: {handler}")
        print(f"  Level: {logging.getLevelName(handler.level)}")
        print(f"  Formatter: {handler.formatter._fmt if handler.formatter else 'None'}")
        print(f"  Filters: {handler.filters}")


def _init_logger(source: str, console_level: str = "INFO", file_level: str = "DEBUG"):
    """Initialise the project logger.

    Levels arrive as plain strings from `runtime.log.{console,file}_level`
    (see ADR-0001). The old `.env.<source>` lookup is gone — callers must
    pass the levels in.
    """
    logging.config.fileConfig(fname=LOGGER_CONF_PATH, disable_existing_loggers=False)
    logger = logging.getLogger()

    if not os.path.isdir("logs"):
        os.makedirs("logs")

    consoleHandler = logger.handlers[0]
    consoleHandler.setLevel(console_level)

    fileHandler = logging.FileHandler(
        "logs/" + source + "_" + datetime.now().strftime("%d-%m-%Y_%H-%M-%S") + ".log"
    )
    formatter = logging.Formatter(
        "%(asctime)s - (%(name)s, %(lineno)d) - %(levelname)s: %(message)s"
    )
    fileHandler.setFormatter(formatter)
    fileHandler.setLevel(file_level)
    logger.addHandler(fileHandler)

    # An extra logging level if required.
    def trace(self, message, *args, **kwargs):
        pass

    level_num = logging.DEBUG - 5
    level_name = "TRACE"
    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), level_name.lower(), trace)
