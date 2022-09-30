# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared import Observation
from CybORG.Shared.Enums import SessionType

from CybORG.Shared.Enums import OperatingSystemType
from CybORG.Simulator.Actions import Action


class GetProcessList(Action):
    """Get a list of all the process IDs for processes running on the host

    Velociraptor Reference
    ----------------------
    Artifact: https://www.velocidex.com/docs/artifacts/linux/#linuxsyspslist
    """

    def __init__(self, session: int, hostname:str, agent: str,
                 ostype: OperatingSystemType):

        super().__init__(session=session,
                         hostname=hostname,
                         agent=agent,
                         artifact='Linux.Sys.Pslist' if ostype == ostype.LINUX else 'Windows.System.Pslist',
                         env={},
                         flow_completion_wait_limit=90)

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.VELOCIRAPTOR_CLIENT:
            return obs

        obs.set_success(True)

        for process in session.hostname.processes:
            obs.add_process(
                hostid="0",
                pid=process.pid,
                process_name=process.name
            )

        return obs
