# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared import Observation
from CybORG.Shared.Enums import SessionType

from .VelociraptorArtifactAction import VelociraptorArtifactAction


class GetProcessInfo(VelociraptorArtifactAction):
    """Get information about a process with process ID PID"""

    def __init__(self, session: int, agent: str, hostname: str, process: int):
        super().__init__(session=session,
                         hostname=hostname,
                         agent=agent,
                         artifact='Linux.Sys.Pslist',
                         env={},
                         flow_completion_wait_limit=90)
        self.pid = process

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.VELOCIRAPTOR_CLIENT:
            return obs

        process = None
        for p in session.host.processes:
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

    def parse(self, results: list, client_id: str) -> Observation:
        """Parses the results of the execute action to create an observation

        See GetProcessList.parse() for description of results format.
        """
        obs = Observation()
        obs.set_success(False)

        for p in results:
            if p["Pid"] != self.pid:
                continue

            obs.set_success(True)
            obs.add_user_info(hostid=client_id, username=p['Username'])

            path = p['Exe']
            if '/' in path:
                path = path.rsplit('/', 1)[0] + '/'
            elif '\\' in path:
                path = path.rsplit('\\', 1)[0] + '\\'

            obs.add_process(
                hostid=client_id,
                pid=p['Pid'],
                parent_pid=p['Ppid'],
                process_name=p['Name'],
                username=p['Username'],
                path=path
            )
            break

        return obs
