# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared import Observation
from CybORG.Shared.Enums import SessionType

from .VelociraptorArtifactAction import VelociraptorArtifactAction


class GetProcessList(VelociraptorArtifactAction):
    """Get a list of all the process IDs for processes running on the host

    Velociraptor Reference
    ----------------------
    Artifact: https://www.velocidex.com/docs/artifacts/linux/#linuxsyspslist
    """

    def __init__(self, session: int, agent: str, hostname: str):
        super().__init__(session=session,
                         hostname=hostname,
                         agent=agent,
                         artifact='Linux.Sys.Pslist',
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

        for process in session.host.processes:
            obs.add_process(
                hostid="0",
                pid=process.pid,
                process_name=process.name
            )

        return obs

    def parse(self, results: list, client_id: str) -> Observation:
        """Parses the results of the execute action to create an observation

        Each result should be in the form:

        {
            'Pid': int,
            'Ppid': int,
            'Name': str,
            'Cmdline': str,
            'Exe': str,
            'Hash': None or dict,
            'Username': str,
            'CreatedTime': timestamp str,
            'RSS': int,
            'Deleted': bool
        }

        Hash dict in form:
        {
            hash_type: hash
        }
        Where hash_type and hash are both strings:

        e.g.
        'Hash': {
            'MD5': 'eb5c...',
            'SHA1': 'dbaad...',
            'SHA256': '6045...''
        }

        """
        obs = Observation()

        if results == []:
            obs.set_success(False)
            return obs
        else:
            obs.add_raw_obs(results)
            obs.set_success(True)

        for p in results:
            obs.add_process(
                hostid=client_id,
                pid=p['Pid'],
                process_name=p['Name'],
                parent_pid=p['Ppid'],
                username=p['Username']
            )

        return obs
