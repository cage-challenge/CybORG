# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Actions.ShellActionsFolder.ServiceManipulationFolder.ServiceManipulation import ServiceManipulation


class StartService(ServiceManipulation):
    def __init__(self, session, agent):
        super().__init__(session, agent)

    def execute(self, state):
        pass