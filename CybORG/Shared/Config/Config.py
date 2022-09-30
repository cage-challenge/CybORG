# Copyright DST Group. Licensed under the MIT license.

import os
import sys
from configparser import ConfigParser

from CybORG.Shared import CybORGLogger
import CybORG.Shared.Config.ConfigHelper as ch


class CybORGConfig(CybORGLogger):

    def __init__(self, config: ConfigParser, test: bool = False, teardown: bool = True):
        """
        Parameters
        ----------
        config : ConfigParser
            the configuration object
        test : bool, optional
            if true uses test configuration (default=False)
        teardown : bool, optional
            if true will shut down Emulator instances (default=False)
        """
        self.config = config
        self.test = test
        self.teardown = teardown

    @staticmethod
    def load_and_setup_logger(config_file_path: str = None,
                              test: bool = False,
                              teardown: bool = True):
        """Load configuration from file, handling case of invalid
        configuration and also setup logger.

        Parameters
        ----------
        config_file_path : str, optional
            path to configuration file, if None will use default
            (default=None)
        test : bool, optional
            if true uses test configuration (default=False)

        teardown : bool, optional
            if true shuts down Emulator instances (default=True)

        Returns
        -------
        CybORGConfig
            loaded configuration object
        """
        cyborg_config = CybORGConfig.load(config_file_path, test, teardown)
        CybORGLogger.setup(cyborg_config)
        return cyborg_config

    @staticmethod
    def load(config_file_path: str = None, test: bool = False, teardown: bool = True):
        """Load configuration from file, handling case of invalid configuration.

        Parameters
        ----------
        config_file_path : str
            path to configuration file, if None will use default
        test : bool, optional
            if true uses test configuration (default=False)
        teardown : bool, optional
            if true shuts down Emulator instances (default=True)

        Returns
        -------
        CybORGConfig
            loaded configuration object
        """

        if config_file_path is None:
            config_file_path = ch.DEFAULT_CONFIG_FILE_PATH
            CybORGLogger.info(f"Using default value for Shared config file path ({config_file_path})")

        if not ch.config_file_valid(config_file_path, ch.SECTION_MAP):
            CybORGLogger.error(f"Error with  config_file_valid ({config_file_path} {ch.SECTION_MAP})")
            # Interactively create a config file
            config_gui = ch.ConfigHelperGUI()
            config_valid, config_file_path = config_gui.run_helper_gui()
            if not config_valid:
                CybORGLogger.error("Can't run CybORG. Please create config file and/or check paths and permissions.")
                sys.exit(-1)
        config_parse = ConfigParser(comment_prefixes=(';','#'))
        config_parse.read(config_file_path)
        return CybORGConfig(config_parse, test, teardown)

    def get_property(self, section, property_name):
        if property_name not in self.config[section]:
            raise AttributeError(f"Config missing property '{property_name}' in section '{section}'")
        return self.config[section][property_name]

    def set_property(self, section, property_name, value):
        if property_name not in self.config[section]:
            raise AttributeError(f"Config missing property '{property_name}' in section '{section}'")
        self.config[section][property_name] = value

    @property
    def cyborg_base_dir(self):
        return self.get_property(ch.DIRS, ch.CYBORG_BASE_DIR)

    @property
    def logger_name(self):
        return self.get_property(ch.LOGGING, ch.LOGGER_NAME)

    @property
    def logger_file_name(self):
        return self.logger_name + f"-{os.getpid()}" + ".txt"

    @property
    def log_to_file(self):
        return self.get_property(ch.LOGGING, ch.LOG_FILE)

    @property
    def log_dir_path(self):
        return self.get_property(ch.LOGGING, ch.LOG_DIR_PATH)

    @property
    def default_console_log_level(self):
        return self.get_property(ch.LOGGING, ch.DEFAULT_CONSOLE_LOG_LEVEL)

    @property
    def default_file_log_level(self):
        return self.get_property(ch.LOGGING, ch.DEFAULT_FILE_LOG_LEVEL)

    @property
    def logging_format(self):
        return ("%(asctime)-13s [ %(process)-6d | %(threadName)-30s]"
                " (%(levelname)-8s) ==> %(message)s")

    @property
    def logging_date_format(self):
        return "%m-%d %H:%M:%S"

    def __str__(self):
        output = f"{self.__class__.__name__}:"
        s = "    "
        for section in self.config.sections():
            output += f"\n{s}{section}:"
            for var_name, var_val in self.config[section].items():
                output += f"\n{s}{s}{var_name}: {var_val}"
        return output

    def __repr__(self):
        output = f"{self.__class__.__name__}:"
        s = "    "
        for section in self.config.sections():
            output += f"\n{s}{section}:"
            for var_name, var_val in self.config[section].items():
                output += f"\n{s}{s}{var_name}: {var_val}"
        return output

    def _format_log_msg(self, msg):
        return f"{self.__class__.__name__} : {msg} "
