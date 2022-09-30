# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Entity import Entity
import enum


class ServiceState(enum.Enum):
    """An enum for representing the different states of services. """
    UNKNOWN = enum.auto()
    OPEN = enum.auto()
    CLOSED = enum.auto()
    FILTERED = enum.auto()

    @classmethod
    def parse_string(cls, service_string):
        if service_string.lower() == "open":
            return cls.OPEN
        elif service_string.lower() == "closed":
            return cls.CLOSED
        elif service_string.lower() == "filtered":
            return cls.FILTERED
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class ServiceVersion(enum.Enum):
    """An enum for representing the different versions of services. """
    UNKNOWN = enum.auto()
    OpenSSH7_6p1 = enum.auto()

    @classmethod
    def parse_string(cls, service_string):
        if service_string.lower() == "openssh 7.6p1":
            return cls.OpenSSH7_6p1
        else:
            return cls.UNKNOWN

    def __str__(self):
        return self.name


class StartupType(enum.Enum):
    """An enum for representing the different startup types of services. """

    @classmethod
    def parse_string(cls, service_string):
        pass

    def __str__(self):
        return self.name


class Service(Entity):
    def __init__(self, name: str = None, port: list = None, state: ServiceState = None, version: ServiceVersion = None,
                 startup_type: StartupType = None, user_running_as: str = None, permissions: dict = None):
        super().__init__()
        self.name = name
        self.state = state
        self.version = version
        self.startup_type = startup_type
        self.user_running_as = user_running_as
        self.permissions = permissions

    def get_state(self):
        pass
