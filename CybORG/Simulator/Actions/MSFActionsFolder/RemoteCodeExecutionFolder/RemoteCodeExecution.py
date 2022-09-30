# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Actions.MSFActionsFolder.MSFAction import MSFAction


class RemoteCodeExecution(MSFAction):
    def __init__(self, session, agent):
        super().__init__(session, agent)

    def execute(self, state):
        pass
