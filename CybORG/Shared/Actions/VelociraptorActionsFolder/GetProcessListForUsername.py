# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation

from .VelociraptorAction import VelociraptorAction


class GetProcessListForUsername(VelociraptorAction):
    """Get a list of the process IDs that are running for a user"""

    def __init__(self, session: int, agent: str, hostname: str, username: str):
        super().__init__(session=session,
                         query_type=QueryType.ASYNC,
                         agent=agent)
        self.agent = agent
        self.hostname = hostname
        self.username = username
        self.parameters['artifactname'] = 'Custom.CybORG.Generic.System.Pslist'
        self.query = (
            "select collect_client("
            "client_id='<host_id>', "
            "artifacts=['Custom.CybORG.Generic.System.Pslist'], "
            "env=dict(agentid='<agentid>', "
            "artifactname='<artifactname>', "
            "tag='<tag>')) FROM scope()"
        )
        self.source_query = (
            "select Pid, Username from source("
            "flow_id='<flowid>', "
            "client_id='<host_id>', "
            "artifact='<artifactname>') "
            "where '<username>' in Username"
        )

    def sim_execute(self, state):
        raise NotImplementedError

    def parse(self, results: list) -> Observation:
        """Parses the results of the execute action to create an observation"""
        obs = Observation()

        if results == []:
            obs.set_success(False)
            return obs
        else:
            obs.set_success(True)

        obs.add_system_info(hostid='0', hostname=self.hostname)

        for p in results:
            if p['Username'] == self.username:
                obs.add_process(
                    hostid='0',
                    pid=p['Pid'],
                    username=self.username
                )
            else:
                user = p['Username'].rsplit('\\')
                if len(user) == 2 and user[1] == self.username:
                    obs.add_process(
                        hostid='0',
                        pid=p['Pid'],
                        username=self.username
                    )
        return obs
