# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.ShellAction import ShellAction
from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Shared.Observation import Observation


class KillProcessLinux(ShellAction):
    # kill -9 <PID>
    def __init__(self, session, agent, process):
        super().__init__(session, agent)
        self.process = process

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        if not state.sessions[self.agent][self.session].active:
            return obs

        host = state.hosts[state.sessions[self.agent][self.session].host]
        obs.add_system_info(hostid="hostid0", os_type=host.os_type)
        if host.os_type == OperatingSystemType.LINUX:
            process = host.get_process(self.process)
            if process is not None:
                obs.set_success(True)
                host.processes.remove(process)
                agent, session = state.get_session_from_pid(pid=self.process, hostname=host.hostname)
                if session is not None:
                    host.sessions[agent].remove(session)
                    session_obj = state.sessions[agent].pop(session)
                    for child in session_obj.children.values():
                        child.set_orphan()
                    if session_obj.parent is not None:
                        state.sessions[agent][session_obj.parent].dead_child(session)

            else:
                obs.set_success(False)

        else:
            obs.set_success(False)
        return obs