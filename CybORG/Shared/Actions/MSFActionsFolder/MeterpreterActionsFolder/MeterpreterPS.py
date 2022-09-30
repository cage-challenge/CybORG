# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.MSFActionsFolder.MeterpreterActionsFolder.MeterpreterAction import MeterpreterAction
from CybORG.Shared.Enums import OperatingSystemType, SessionType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# Call ps from a meterpreter session - gives a list of processes with PID, name, user and path
class MeterpreterPS(MeterpreterAction):
    def __init__(self, session: int, agent: str):
        super().__init__(session=session, agent=agent)

    def sim_execute(self, state: State):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.METERPRETER or not session.active:
            return obs

        obs.set_success(True)
        users = []
        proc_sh = session.host.add_process(name="sh", user=session.user, path="/bin/")
        proc_ps = session.host.add_process(name="ps", user=session.user)

        if session.host.os_type == OperatingSystemType.LINUX:
            root = False
            for group in session.user.groups:
                if group.uid == 0:
                    root = True
                # Is this the best way to check this? Can group name be changed, is there some other way to check if it
                # is a user with minimal privileges?
                elif group.name == "nogroup":
                    for proc in session.host.processes:
                        if proc.user.username not in users:
                            users.append(proc.user.username)
                        obs.add_process(hostid="0", pid=proc.pid, process_name=proc.name,
                                        username=proc.user.username, path=proc.path)
                    for user in users:
                        obs.add_user_info(hostid="0", username=user)
                    # Need to be able to remove processes as well - remove /bin/sh and ps processes created above?
                    state.remove_process(host=session.host.hostname, pid=proc_sh.pid)
                    state.remove_process(host=session.host.hostname, pid=proc_ps.pid)
                    return obs

            obs.add_system_info(hostid="0", architecture=session.host.architecture)
            if root:
                state.remove_process(host=session.host.hostname, pid=proc_sh.pid)
                state.remove_process(host=session.host.hostname, pid=proc_ps.pid)
                for proc in session.host.processes:
                    if proc.user.username not in users:
                        users.append(proc.user.username)
                    obs.add_process(hostid="0", pid=proc.pid, process_name=proc.name,
                                    username=proc.user.username, parent_pid=proc.ppid, path=proc.path)
            else:
                state.remove_process(host=session.host.hostname, pid=proc_sh.pid)
                state.remove_process(host=session.host.hostname, pid=proc_ps.pid)
                for proc in session.host.processes:
                    if proc.user is not None and proc.user.username not in users:
                        users.append(proc.user.username)
                    obs.add_process(hostid="0", pid=proc.pid, process_name=proc.name,
                                    username=proc.user.username, parent_pid=proc.ppid)
            for user in users:
                obs.add_user_info(hostid="0", username=user)
            return obs

        else:
            state.remove_process(host=session.host.hostname, pid=proc_sh.pid)
            state.remove_process(host=session.host.hostname, pid=proc_ps.pid)
            obs.add_system_info(hostid="0", architecture=session.host.architecture)
            for proc in session.host.processes:
                if proc.user is not None and proc.user.username not in users:
                    users.append(proc.user.username)
                obs.add_process(hostid="0", pid=proc.pid, process_name=proc.name,
                                username=proc.user.username, parent_pid=proc.ppid, path=proc.path)
            for user in users:
                obs.add_user_info(hostid="0", username=user)
            return obs
