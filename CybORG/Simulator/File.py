# Copyright DST Group. Licensed under the MIT license.
from datetime import datetime

from CybORG.Shared.Enums import FileType, FileVersion
from CybORG.Simulator.Entity import Entity
from CybORG.Simulator.LocalGroup import LocalGroup
from CybORG.Simulator.User import User
import enum


class File(Entity):
    def __init__(self, name: str, path: str, user: User, user_permissions: int = None,
                 group: str = None, group_permissions: int = None, default_permissions: int = None,
                 create_time: str = None, last_modified_time: str = None,
                 last_access_time: str = None, file_type: str = None, vendor: str = None, version: str = None,
                 density=0, signed=False):
        super().__init__()
        self.name = name
        self.path = path
        self.user = user
        self.user_permissions = user_permissions
        if self.user_permissions is None and self.user is not None:
            self.group_permissions = 7
        self.group = group
        self.group_permissions = group_permissions
        if self.group_permissions is None and self.group is not None:
            self.group_permissions = 7
        self.default_permissions = default_permissions
        if self.default_permissions is None:
            self.default_permissions = 7
        self.create_time = create_time
        self.last_modified_time = last_modified_time
        if self.last_modified_time is not None:
            self.last_modified_time = datetime.strptime(self.last_modified_time, "%d %b %Y %H:%M")
        self.last_access_time = last_access_time
        self.file_type = FileType.UNKNOWN
        if file_type is not None:
            if type(file_type) is not FileType:
                file_type = FileType.parse_string(file_type)
            self.file_type = file_type
        self.vendor = vendor
        self.version = None
        if version is not None:
            self.version = FileVersion.parse_string(version)

        self.density = density
        self.signed = signed

    def get_state(self):
        obs = {"path": self.path,
               "name": self.name,
               "vendor": self.vendor,
               "version": self.version,
               "file_type": self.file_type,
               "user_permissions": self.user_permissions,
               "group": self.group,
               "group_permissions": self.group_permissions,
               "default_permissions": self.default_permissions,
               "last_modified_time": self.last_modified_time,
               "user": self.user}
        return obs

    # Checks if the file is executable by a given user - assumes the user and file are on the same dict
    def check_executable(self, user: User):
        if self.default_permissions % 2:
            return True
        if self.group in user.groups and self.group_permissions % 2:
            return True
        if self.user == user and self.user_permissions % 2:
            return True
        return False

    def check_readable(self, user: User):
        if self.default_permissions >= 4:
            return True
        if self.group in user.groups and self.group_permissions >= 4:
            return True
        if self.user == user.username and self.user_permissions >= 4:
            return True
        if user.username == 'SYSTEM':
            return True
        return False
