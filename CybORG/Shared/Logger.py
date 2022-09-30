# Copyright DST Group. Licensed under the MIT license.
import sys
import logging
import paramiko
import os.path as osp


class CybORGLogger:
    """A logger class for CybORG.

    It has two main functions:
    1. acts as a wrapper for the Python logger class
    2. provides a base class with useful logging function that other classes
    can inherit and use to make logging easier.
    """

    logger_name = "CybORGLog-Process"
    sshtunnel_logger_name = f"{logger_name}-sshtunnel"

    # Add extra levels to logging
    DEBUG2 = "DEBUG2"
    DEBUG2_LVL = logging.DEBUG-1
    logging.addLevelName(DEBUG2_LVL, DEBUG2)

    @staticmethod
    def setup(config, verbosity: int = None):
        """Setup the CybORG logger using given configuration.

        Arguments
        ---------
        config : CybORGConfig
            the configuration object
        verbosity : int, optional
            verbosity level of console logger, if None uses level in config.
            Level 0 = logging.WARNING (30) and above
            Level 1 = logging.INFO (20) and above
            Level 2 = logging.WARNING (10) and above
            Level 3 = CybORGLogger.DEBUG2 (9) and above (i.e. will show
                      messages logged with the debug2() method.
            Level 4+ = logging.NOTSET (0) and above (i.e. will display all
                       logged information)
        """
        console_log_level = config.default_console_log_level
        if verbosity:
            assert verbosity >= 0, "Invalid verbosity, must be >= 0"
            if verbosity <= 2:
                console_log_level = logging.WARNING - verbosity*10
            elif verbosity == 3:
                console_log_level = CybORGLogger.DEBUG2
            else:
                console_log_level = logging.NOTSET

        CybORGLogger.logger_name = config.logger_name
        formatter = logging.Formatter(
            fmt=config.logging_format, datefmt=config.logging_date_format
        )
        console_log_level = logging.getLevelName(console_log_level)
        file_log_level = logging.getLevelName(config.default_file_log_level)
        logger = logging.getLogger(config.logger_name)

        # create console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(console_log_level)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # set the log level of the logger itself
        logger.setLevel(console_log_level)

        # Do NOT propogate log messages to the root logger
        logger.propagate = False

        if config.log_to_file:
            log_file = osp.join(config.log_dir_path, config.logger_file_name)
            fh = logging.FileHandler(filename=log_file, mode='w')
            fh.setLevel(file_log_level)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
            logger.setLevel(file_log_level)

        ##################################################################
        # Paramiko logging config
        ##################################################################
        paramiko_logger_name = f"{config.logger_name}-paramiko"
        paramiko_logger = paramiko.util.get_logger("paramiko")
        # Suppress paramiko's verbose output to stdout
        paramiko_log_file = osp.join(
            config.log_dir_path, paramiko_logger_name + ".log"
        )
        paramiko.util.log_to_file(paramiko_log_file, level="WARN")
        paramiko_logger.setLevel(logging.WARNING)
        paramiko_logger.propagate = False  # don't dump on console

        ##################################################################
        # SSHTunnel logging config
        ##################################################################
        ssht_log_format = "%(asctime)-15s (%(levelname)-8s) ==> %(message)s"
        ssht_formatter = logging.Formatter(
            fmt=ssht_log_format, datefmt=config.logging_date_format
        )

        # note this is not the default logger name for SSHTunnel,
        # just a name chosen for CybORG
        sshtunnel_logger_name = f"{config.logger_name}-sshtunnel"
        sshtunnel_logger = logging.getLogger(sshtunnel_logger_name)
        # Don't dump sshtunnel outputs to console
        sshtunnel_logger.propagate = False
        if config.log_to_file:
            # create file handler
            ssh_log_file = osp.join(
                config.log_dir_path, sshtunnel_logger_name + ".txt"
            )
            sfh = logging.FileHandler(ssh_log_file, mode='w')
            sfh.setLevel(file_log_level)
            # create formatter and add it to the handlers
            sfh.setFormatter(ssht_formatter)
            # add the handlers to the sshtunnel_logger
            sshtunnel_logger.addHandler(sfh)

    @staticmethod
    def setLevel(level):
        logging.getLogger(
            CybORGLogger.logger_name
        ).setLevel(level=level)

    @staticmethod
    def debug(msg, *args, **kwargs):
        logging.getLogger(
            CybORGLogger.logger_name
        ).debug(msg, *args, **kwargs)

    @staticmethod
    def debug2(msg, *args, **kwargs):
        logging.getLogger(
            CybORGLogger.logger_name
        ).log(CybORGLogger.DEBUG2_LVL, msg, *args, **kwargs)

    @staticmethod
    def info(msg, *args, **kwargs):
        logging.getLogger(
            CybORGLogger.logger_name
        ).info(msg, *args, **kwargs)

    @staticmethod
    def warning(msg, *args, **kwargs):
        logging.getLogger(
            CybORGLogger.logger_name
        ).warning(msg, *args, **kwargs)

    @staticmethod
    def error(msg, *args, **kwargs):
        logging.getLogger(
            CybORGLogger.logger_name
        ).error(msg, *args, **kwargs)

    @staticmethod
    def critical(msg, *args, **kwargs):
        logging.getLogger(
            CybORGLogger.logger_name
        ).critical(msg, *args, **kwargs)

    @staticmethod
    def header(title):
        CybORGLogger.info(f"\n\n{'':*^30} {title:^50} {'':*^30}\n\n")

    @staticmethod
    def get_logger():
        return logging.getLogger(CybORGLogger.logger_name)

    @staticmethod
    def get_ssh_tunnel_logger():
        return logging.getLogger(CybORGLogger.sshtunnel_logger_name)

    def _log_header(self, title):
        CybORGLogger.header(self._format_log_msg(title))

    def _log_info(self, msg):
        CybORGLogger.info(self._format_log_msg(msg))

    def _log_error(self, msg):
        CybORGLogger.error(self._format_log_msg(msg))

    def _log_debug(self, msg):
        CybORGLogger.debug(self._format_log_msg(msg))

    def _log_debug2(self, msg):
        CybORGLogger.debug2(self._format_log_msg(msg))

    def _log_warning(self, msg):
        CybORGLogger.warning(self._format_log_msg(msg))

    def _format_log_msg(self, msg):
        """Overide this function for more informative logging messages """
        return f"{self.__class__.__name__}: {msg}"


def log_trace(func):
    """Logger decorator for logging function execution.

    Import this function and add @log_trace above your function of
    interest to log output to file about the functions execution
    """
    def call(*args, **kwargs):
        """ Actual wrapping """
        entering(func, *args)
        result = func(*args, **kwargs)
        exiting(func)
        return result
    return call


def entering(func, *args):
    """ Pre function logging """
    CybORGLogger.debug("Entered %s", func.__name__)
    CybORGLogger.debug(func.__doc__)
    CybORGLogger.debug(
        "Function at line %d in %s" % (func.__code__.co_firstlineno,
                                       func.__code__.co_filename)
    )

    try:
        CybORGLogger.debug(
            "The argument %s is %s" % (func.__code__.co_varnames[0], *args)
        )
    except IndexError:
        CybORGLogger.debug("No arguments")


def exiting(func):
    """ Post function logging """
    CybORGLogger.debug("Exited  %s", func.__name__)
