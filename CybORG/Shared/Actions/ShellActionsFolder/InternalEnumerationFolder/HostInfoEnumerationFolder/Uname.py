# Copyright DST Group. Licensed under the MIT license.
from .HostInfoEnumeration import HostInfoEnumeration
from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Shared.Observation import Observation


class Uname(HostInfoEnumeration):

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs

        if state.sessions[self.agent][self.session].active:
            host = state.sessions[self.agent][self.session].host
            if host.os_type == OperatingSystemType.LINUX:
                obs.set_success(True)
                obs.add_system_info(**(host.get_state()))
            else:
                obs.add_system_info(os_type=host.os_type)
                obs.set_success(False)
        else:
            obs.set_success(False)
        return obs

    def emu_execute(self, session_handler, *args, **kwargs):
        cmd = "uname"
        obs = Observation()
