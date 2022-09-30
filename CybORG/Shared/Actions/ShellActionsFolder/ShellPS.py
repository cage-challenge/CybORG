# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.ShellAction import ShellAction
from CybORG.Shared.Enums import OperatingSystemType, SessionType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# Call 'ps -o user,uid,pid,ppid,command ax' from a shell or msf shell session
# gives a list of processes with user, UID, PID, PPID, name, and path
# Note other potentially useful params after -o include: group, gid, eip, esp, stat
class ShellPS(ShellAction):
    def __init__(self, session: int, agent: str):
        super().__init__(session=session, agent=agent)

    def sim_execute(self, state: State):
        obs = Observation()
        obs.set_success(False)
        if self.session in state.sessions[self.agent]:
            session = state.sessions[self.agent][self.session]

            if session.active:
                if session.host.os_type != OperatingSystemType.LINUX:
                    return obs

                if session.session_type != SessionType.SHELL and session.session_type != SessionType.MSF_SHELL:
                    return obs

                obs.add_system_info(hostid="0", os_type="linux")

                obs.set_success(True)
                users = []
                proc_ps = session.host.add_process(name="ps", user=session.user)

                for proc in session.host.processes:
                    if proc.user.username not in users:
                        users.append(proc.user)
                    obs.add_process(hostid="0", pid=proc.pid, process_name=proc.name,
                                    username=proc.user.username, parent_pid=proc.ppid, path=proc.path)

                for user in users:
                    obs.add_user_info(hostid="0", username=user.username, uid=user.uid)
                state.remove_process(host=session.host.hostname, pid=proc_ps.pid)

        return obs
