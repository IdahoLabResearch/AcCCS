import logging
import os
from dataclasses import dataclass
from typing import Optional

import environs

from app.shared.network import validate_nic
from app.shared.settings import load_shared_settings, shared_settings

logger = logging.getLogger(__name__)


@dataclass
class Config:
    iface: Optional[str] = None
    console_log_level: Optional[str] = None
    file_log_level: Optional[str] = None
    ev_config_file_path: str = None

    def load_envs(self, env_path: Optional[str] = None) -> None:
        """
        Tries to load the .env file containing all the project settings.
        If `env_path` is not specified, it will get the .env on the current
        working directory of the project

        Args:
            env_path (str): Absolute path to the location of the .env file
        """
        env = environs.Env(eager=False)
        if not env_path:
            env_path = os.getcwd() + "/.env.evcc"
        env.read_env(path=env_path)  # read .env file, if it exists

        self.iface = env.str("NETWORK_INTERFACE", default="eth0")
        # validate the NIC selected
        validate_nic(self.iface)

        self.console_log_level = env.str("CONSOLE_LOG_LEVEL", default="INFO")
        self.file_log_level = env.str("FILE_LOG_LEVEL", default="DEBUG")

        self.ev_config_file_path = str(
            env.path(
                "EVCC_CONFIG_PATH",
                default="app/shared/examples/evcc/iso15118_2/evcc_config_eim_ac.json",  # noqa
            )
        )
        env.seal()  # raise all errors at once, if any
        load_shared_settings()
        logger.info("EVCC environment settings:")
        for key, value in shared_settings.items():
            logger.info(f"{key:30}: {value}")
        for key, value in env.dump().items():
            logger.info(f"{key:30}: {value}")


RESUME_SELECTED_AUTH_OPTION = None
RESUME_SESSION_ID = None
RESUME_REQUESTED_ENERGY_MODE = None
