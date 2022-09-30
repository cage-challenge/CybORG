# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared import Observation
from CybORG.Shared.Enums import SessionType

from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Simulator.Actions import Action


class GetProcessInfo(Action):
    """Get information about a process with process ID PID"""

    def __init__(self, session: int, hostname: str, agent: str, process: int,
                 ostype: OperatingSystemType):
        super().__init__(session=session,
                         hostname=hostname,
                         agent=agent,
                         artifact='Linux.Sys.Pslist' if ostype == ostype.LINUX else 'Windows.System.Pslist',
                         env={},
                         flow_completion_wait_limit=90)
        self.pid = process
        self.os = ostype


    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.VELOCIRAPTOR_CLIENT:
            return obs

        process = None
        for p in session.hostname.processes:
            if p.pid == self.pid:
                process = p
                break

        if process is None:
            return obs

        obs.set_success(True)
        obs.add_process(
            hostid="0",
            pid=process.pid,
            parent_pid=process.ppid,
            path=process.path,
            process_name=process.name,
            username=process.user.username
        )
        obs.add_user_info(hostid="0", username=process.user.username)

        return obs
