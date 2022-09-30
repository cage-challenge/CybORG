# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Actions.ShellActionsFolder.OpenConnectionFolder.OpenConnection import OpenConnection


class CredentialAccess(OpenConnection):
    def __init__(self, session, agent):
        super().__init__(session, agent)

    def execute(self, state):
        pass
