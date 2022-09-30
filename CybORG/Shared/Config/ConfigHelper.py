import os
import errno
import os.path as osp
from configparser import ConfigParser


def get_parent_dir_path(path):
    """Returns the path to the parent directory in path. """
    if osp.isfile(path):
        return osp.dirname(path)
    return osp.dirname(osp.abspath(path))


# Default file names
CONFIG_FILE_NAME = "config.ini"
DEFAULT_VALUES_FILE_NAME = "defaultconfig.ini"


# Default config dir = dir this file is in
DEFAULT_CONFIG_DIR = osp.dirname(osp.abspath(__file__))

# DEFAULT CYBORG DIR = parent dir of config dir
DEFAULT_CYBORG_DIR = get_parent_dir_path(
    get_parent_dir_path(DEFAULT_CONFIG_DIR)
)

# DEFAULT_CONFIG_FILE_PATH
DEFAULT_CONFIG_FILE_PATH = osp.join(DEFAULT_CONFIG_DIR, CONFIG_FILE_NAME)

# Keys for sections of config file
DIRS = "DIRS"
LOGGING = "LOGGING"

# Keys for config variables
CYBORG_BASE_DIR = "cyborg_base_dir"
LOGGER_NAME = "logger_name"
LOG_FILE = "log_file"
LOG_DIR_PATH = "log_dir_path"
DEFAULT_CONSOLE_LOG_LEVEL = "default_console_log_level"
DEFAULT_FILE_LOG_LEVEL = "default_file_log_level"

SECTION_MAP = {
    DIRS: [CYBORG_BASE_DIR],
    LOGGING: [
        LOGGER_NAME,
        LOG_FILE,
        LOG_DIR_PATH,
        DEFAULT_CONSOLE_LOG_LEVEL,
        DEFAULT_FILE_LOG_LEVEL
    ]
}

INI_FILETYPES = (("ini files", "*.ini"), ("all files", "*.*"))
KEY_FILETYPES = (("key files", "*.pem"), ("all files", "*.*"))


def config_file_valid(config_file_path: str, section_map: dict) -> bool:
    """Checks to see if config file exists and is valid

    Parameters
    ----------
    config_file : str
        Path to config file to check
    section_map : dict
        dictionary of expected sections and variables within config file

    Returns
    -------
    bool
        True if config file exists and is valid
    """
    if not osp.isfile(config_file_path):
        return False

    try:
        config = ConfigParser()
        config.read(config_file_path)

        if not validate_config_file(config, section_map):
            return False

        file_dirs = [config[DIRS][CYBORG_BASE_DIR],
                     config[LOGGING][LOG_DIR_PATH]]
        if not validate_file_dirs(file_dirs):
            return False
        return True

    except Exception:
        return False


def validate_config_file(config: ConfigParser, section_map: dict) -> bool:
    """Check that config file is valid and contains all expected variables.

    Parameters
    ----------
    config: ConfigParser
        Config to validate
    section_map : dict
        dictionary of expected sections and variables within config file

    Returns
    -------
    bool
        True if config file is valid
    """
    # Check all the variables are there
    for section, config_vars in section_map.items():
        for var in config_vars:
            if var not in config[section]:
                print(f"Config file invalid, variable '{var}' missing"
                      f" from '{section}' section")
                return False
    return True


def validate_file_dirs(file_dirs: list) -> bool:
    """Check that all directories designated are valid.

    Parameters
    ----------
    file_dirs: list
        list of directory paths

    Returns
    -------
    bool
        True if all directory paths are valid.
    """
    for f in file_dirs:
        if not osp.isdir(f):
            return False
    return True


def file_path_valid(file_path: str) -> bool:
    """Check file path is a valid file.

    Parameters
    ----------
    file_path : str
        the file path

    Returns
    -------
    bool
        True if the file path is valid
    """
    return osp.isfile(file_path)


def validate_file_paths(file_paths: list) -> bool:
    """Check that all files paths in config file are valid.

    Parameters
    ----------
    file_paths : list
        list of file paths

    Returns
    -------
    bool
        True if all file paths are valid
    """
    for fp in file_paths:
        if not osp.isfile(fp):
            return False
    return True


def remove_file_if_exists(filepath: str):
    """Remove a file at location if it exists. """
    try:
        os.remove(filepath)
    except OSError as e:
        if e.errno != errno.ENOENT:
            # errno.ENOENT = no such file or directory
            # re-raise exception if a different error occurred
            raise e


def ask_yes_no_question(question: str) -> bool:
    """Ask user a yes/no question in terminal.

    Parameters
    ----------
    question: str
        The question to ask the user

    Returns
    -------
    bool
        True if the user answered 'yes', False if user answered 'no'
    """
    while True:
        yes_no = input(f"{question} [y|n] ")
        if yes_no.strip().lower() == "y":
            return True
        elif yes_no.strip().lower() == "n":
            return False
        else:
            print("\tPlease just type 'y' or 'n'")


def ask_file_path(question: str) -> str:
    """Ask user to provide the path to a file.

    Parameters
    ----------
    question: str
        The question to ask the user

    Returns
    -------
    str
       the user supplied file path
    """
    while True:
        fp = input(f"{question}:")
        if file_path_valid(fp):
            return fp
        print("Invalid file path. Try again.")


def ask_file_dir(question: str) -> str:
    """Ask user to provide the path to a directory.

    Parameters
    ----------
    question: str
        The question to ask the user

    Returns
    -------
    str
       the user supplied file path
    """
    while True:
        fp = input(f"{question}:")
        if osp.isdir(fp):
            return fp
        print("Invalid directory path. Try again.")


class ConfigHelperGUI:
    """Class for running Config creation GUI. """

    def __init__(self):
        self.init_dir = DEFAULT_CONFIG_DIR
        self.default_config_file_path = DEFAULT_CONFIG_FILE_PATH
        self.default_values_file_name = DEFAULT_VALUES_FILE_NAME
        self.config_file_name = CONFIG_FILE_NAME
        self.default_cyborg_dir = DEFAULT_CYBORG_DIR

    def run_helper_gui(self):
        """Run Config Helper GUI.

        Returns
        -------
        config_valid : bool
            whether valid config exists
        config_file_path : str
            path to config file, if it exists
        """
        try:
            if not self._user_wants_to_create_new_file():
                return False, ""

            self.config_file_path = self._get_config_file_path()
            if config_file_valid(self.config_file_path, SECTION_MAP):
                if self._use_existing_file():
                    return True, self.config_file_path
                remove_file_if_exists(self.config_file_path)

            self.default_config = self._load_default_config()
            new_config = self._create_new_config()
            self._write_new_config(new_config, self.config_file_path)
            return True, self.config_file_path

        except Exception as ex:
            print(f"Exception creating config file: \n{str(ex)}")
            return False, ""

    def _user_wants_to_create_new_file(self):
        question = (f"ERROR: The config file '{self.default_config_file_path}'"
                    "does not exist or is invalid. Would you like to create "
                    " one now?")
        if not ask_yes_no_question(question):
            print("Can't run CybORG. Please create config file and/or "
                  "check paths and permissions.")
            return False
        return True

    def _get_config_file_path(self):
        print(f"Creating config file at {self.default_config_file_path}")
        return osp.abspath(self.default_config_file_path)

    def _use_existing_file(self):
        question = (f"The config file \"{self.config_file_path}\" exists. "
                    "Would you like to use it (say no to create new one)?")
        if ask_yes_no_question(question):
            return True
        return False

    def _load_default_config(self):
        default_config_path = osp.join(self.init_dir,
                                       self.default_values_file_name)
        if not osp.isfile(default_config_path):
            title = "Please locate the default config file"
            fp = ask_file_path(title)
            default_config_path = osp.abspath(fp)

        config_parse = ConfigParser()
        config_parse.read(default_config_path)
        return config_parse

    def _create_new_config(self):
        print(f"Creating new config file...")
        new_config = ConfigParser()

        self._config_dirs(new_config)
        self._config_logging(new_config)
        return new_config

    def _config_dirs(self, new_config):
        print(f"\nConfiguration for CybORG Shared: {DIRS}")
        new_config[DIRS] = {}
        for var in SECTION_MAP[DIRS]:
            if var == CYBORG_BASE_DIR:
                self.base_dir = self._get_base_dir()
                new_config[DIRS][var] = self.base_dir
            else:
                value = self._get_config_value(DIRS, var)
                new_config[DIRS][var] = value

    def _get_base_dir(self):
        base_dir = self.default_cyborg_dir
        question = f"CybORG source directory is {base_dir}, is that correct?"
        if not ask_yes_no_question(question):
            title = "Please locate the CybORG source directory"
            base_dir = ask_file_dir(title)

        if osp.isdir(base_dir):
            return base_dir

        raise Exception("Create config file failed, the base directory of the "
                        f" repository ({base_dir}), is not  valid.")

    def _config_logging(self, new_config):
        print(f"\nConfiguration for CybORG Shared: {LOGGING}")
        new_config[LOGGING] = {}
        for var in SECTION_MAP[LOGGING]:
            if var == LOG_DIR_PATH:
                log_dir = self._get_log_dir()
                new_config[LOGGING][var] = log_dir
            else:
                value = self._get_config_value(LOGGING, var)
                new_config[LOGGING][var] = value

    def _get_log_dir(self):
        log_dir = osp.join(self.base_dir,
                           self.default_config[LOGGING][LOG_DIR_PATH])
        question = (f"Logs will be written to directory ({log_dir}), "
                    "do you wish to specify a different directory?")
        if ask_yes_no_question(question):
            title = "Please choose a log directory"
            log_dir = ask_file_dir(title)

        if not osp.isdir(log_dir):
            os.makedirs(log_dir)
        return log_dir

    def _get_config_value(self, section, var):
        default = self.default_config[section][var]
        if isinstance(default, bool):
            input_var = input(f"Do you want to {var} (default={default}):")
        else:
            input_var = input(f"Please enter {var} (default={default}):")
        if not input_var:
            input_var = default
        return input_var

    def _write_new_config(self, new_config, config_file_path):
        with open(config_file_path, 'w') as newini:
            new_config.write(newini)


if __name__ == "__main__":
    ConfigHelperGUI().run_helper_gui()
