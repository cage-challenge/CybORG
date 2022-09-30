# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Entity import Entity


class LocalGroup(Entity):
    def __init__(self, name: str = None, gid: int = None, users: list = None):
        super().__init__()
        self.name = name
        self.ident = gid
        self.users = users

    def get_state(self):
        return {"group": self.name,
                "gid": self.ident}

    def remove_user(self, user):
        for candidate in self.users:
            if user == candidate.username:
                self.users.remove(candidate)

