# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.ShellAction import ShellAction
from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Shared.Observation import Observation


class KillProcessWindows(ShellAction):
    # taskkill /PID  processId
    def __init__(self, session, process, agent):
        super().__init__(session, agent)
        self.process = process

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        if not state.sessions[self.agent][self.session].active:
            return obs

        host = state.sessions[self.agent][self.session].host
        obs.add_system_info(hostid="hostid0", os_type=host.os_type)
        if host.os_type == OperatingSystemType.WINDOWS:
            process = host.get_process(self.process)
            if process is not None:
                obs.set_success(True)
                host.processes.remove(process)
                session, agent = host.get_session(pid=self.process)
                if session is not None:
                    host.sessions[agent].remove(session)
                    state.sessions[agent].pop(session.ident)
            else:
                obs.set_success(False)
        else:
            obs.set_success(False)
        return obs