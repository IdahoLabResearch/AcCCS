import logging.config
import os
from datetime import datetime

import environs

LOGGING_DIR = os.path.dirname(os.path.abspath(__file__))
LOGGER_CONF_PATH = os.path.join(LOGGING_DIR, "logging.conf")


# TODO: find a way to inject the log level setting from the evcc_settings or
# secc_settings Config file, instead of getting the log level again from the .env here

def print_logging_settings():
    logger = logging.getLogger()
    print(f"Logger name: {logger.name}")
    print(f"Logger level: {logging.getLevelName(logger.level)}")
    
    for handler in logger.handlers:
        print(f"\nHandler: {handler}")
        print(f"  Level: {logging.getLevelName(handler.level)}")
        print(f"  Formatter: {handler.formatter._fmt if handler.formatter else 'None'}")
        print(f"  Filters: {handler.filters}")

def log_levels(source: str):
    WORK_DIR = os.getcwd()
    ENV_PATH = WORK_DIR + "/.env."+source.lower()
    env = environs.Env(eager=False)
    env.read_env(path=ENV_PATH)  # read .env file, if it exists
    CONSOLE_LOG_LEVEL = env.str("CONSOLE_LOG_LEVEL", default="INFO")
    FILE_LOG_LEVEL = env.str("FILE_LOG_LEVEL", default="DEBUG")
    env.seal()  # raise all errors at once, if any
    return CONSOLE_LOG_LEVEL, FILE_LOG_LEVEL


def _init_logger(source: str):
    logging.config.fileConfig(fname=LOGGER_CONF_PATH, disable_existing_loggers=False)
    CONSOLE_LOG_LEVEL, FILE_LOG_LEVEL = log_levels(source)
    logger = logging.getLogger()
    
    if not os.path.isdir("logs"):
        os.makedirs("logs")
    
    consoleHandler = logger.handlers[0]
    consoleHandler.setLevel(CONSOLE_LOG_LEVEL)
    
    fileHandler = logging.FileHandler("logs/"+source+"_"+datetime.now().strftime("%d-%m-%Y_%H-%M-%S")+".log")
    formatter = logging.Formatter("%(asctime)s - (%(name)s, %(lineno)d) - %(levelname)s: %(message)s")
    fileHandler.setFormatter(formatter)
    fileHandler.setLevel(FILE_LOG_LEVEL)
    logger.addHandler(fileHandler)
    
    # print_logging_settings()

    # An extra logging level if required.
    def trace(self, message, *args, **kwargs):
        pass

    level_num = logging.DEBUG - 5
    level_name = "TRACE"
    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), level_name.lower(), trace)
