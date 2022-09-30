# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Actions.ShellActionsFolder.InternalEnumerationFolder. \
    InternalEnumeration import InternalEnumeration


class HostInfoEnumeration(InternalEnumeration):

    def __init__(self, session: int, agent: str = None):
        super().__init__(session, agent)

    def execute(self, state):
        pass
