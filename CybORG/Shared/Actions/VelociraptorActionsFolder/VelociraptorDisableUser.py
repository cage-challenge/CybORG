# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation

from .VelociraptorAction import VelociraptorAction


class VelociraptorDisableUser(VelociraptorAction):
    """Disables the account of a user on a host"""

    def __init__(self, session: int, agent: str, hostname: str, username: str):
        super().__init__(session=session,
                         query_type=QueryType.ASYNC,
                         agent=agent)
        self.agent = agent
        self.hostname = hostname
        self.username = username
        self.parameters['artifactname'] = 'Custom.CybORG.Generic.RunCommand'
        self.query = (
            'select collect_client(client_id="<host_id>", '
            'artifacts=["Custom.CybORG.Generic.RunCommand", '
            '"Custom.CybORG.Generic.RunOtherCommand"]], '
            'env=dict(command="net!user!<username>!/active:no", '
            'othercommand="chage!-E0!<username>")) FROM scope()'
        )
        self.source_query = (
            "select * from chain(a={select * from "
            "source(flow_id='<flowid>', client_id='<host_id>',"
            " artifact='Custom.CybORG.Generic.RunCommand')}, "
            "b={select * from "
            "source(flow_id='<flowid>', client_id='<host_id>', "
            "artifact='Custom.CybORG.Generic.RunOtherCommand')})"
        )

    def sim_execute(self, state):
        raise NotImplementedError

    def parse(self, results: list) -> Observation:
        """Parses the results of the execute action to create an observation"""
        obs = Observation()
        if results[0]['stderr'] == '' or results[1]['stderr'] == '':
            obs.set_success(True)
        else:
            obs.set_success(False)
        return obs
