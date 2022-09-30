# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.ShellAction import ShellAction
from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Shared.Observation import Observation


class IPConfig(ShellAction):
    def __init__(self, session, agent):
        super().__init__(session, agent)

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs

        if state.sessions[self.agent][self.session].active:
            host = state.sessions[self.agent][self.session].host
            obs.add_system_info(hostid="hostid0", os_type=host.os_type)
            if host.os_type == OperatingSystemType.WINDOWS:
                obs.set_success(True)
                for interface in host.interfaces:
                    obs.add_interface_info(hostid="hostid0", **(interface.get_state()))
        return obs