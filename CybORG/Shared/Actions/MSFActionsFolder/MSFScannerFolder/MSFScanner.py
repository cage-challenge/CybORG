# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import MSFAction
from CybORG.Simulator.State import State


class MSFScanner(MSFAction):
    def __init__(self, session, agent):
        super().__init__(session, agent)

    def sim_execute(self, state: State):
        pass
