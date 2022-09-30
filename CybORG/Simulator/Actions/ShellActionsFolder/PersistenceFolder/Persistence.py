# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Actions.ShellActionsFolder.ShellAction import ShellAction


class Persistence(ShellAction):
    def __init__(self, session, agent):
        super().__init__(session, agent)

    def execute(self, state):
        pass
