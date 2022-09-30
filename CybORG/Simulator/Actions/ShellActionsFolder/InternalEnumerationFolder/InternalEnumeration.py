# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Actions.ShellActionsFolder.ShellAction import ShellAction


class InternalEnumeration(ShellAction):

    def __init__(self, session: int, agent: str = None):
        super().__init__(session, agent)

    def execute(self, state):
        pass
