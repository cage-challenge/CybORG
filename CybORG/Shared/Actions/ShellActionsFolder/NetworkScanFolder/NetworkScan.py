# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.ShellAction import ShellAction


class NetworkScan(ShellAction):
    def __init__(self, session, agent, subnet):
        super().__init__(session, agent)
        self.subnet = subnet

    def sim_execute(self, state):
        pass
