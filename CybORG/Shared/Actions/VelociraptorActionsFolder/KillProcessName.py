# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation

from .VelociraptorAction import VelociraptorAction


class KillProcessName(VelociraptorAction):
    """Kill a process with the given name"""

    def __init__(self,
                 session: int,
                 agent: str,
                 hostname: str,
                 process_name: str):
        super().__init__(session=session,
                         query_type=QueryType.ASYNC,
                         agent=agent)
        self.agent = agent
        self.hostname = hostname
        self.process_name = process_name
        self.parameters['artifactname'] = 'Custom.CybORG.Generic.RunClientCommand'
        self.query = (
            'select collect_client('
            'client_id="<host_id>", '
            'artifacts=["Custom.CybORG.Generic.RunClientCommand", '
            '"Custom.CybORG.Generic.RunOtherCommand"], '
            'env=dict(command="taskkill!/IM!<process_name>!/f", '
            'othercommand="killall!-9!<process_name>")) '
            'FROM scope()'
        )
        # TODO: Note there is currently no Custom.CybORG.Generic.RunOtherCommand artifact
        # The source_query doesn't include the query, so this needs to be investigated

        self.source_query = (
            "select * from chain("
            "a={select * from source("
            "flow_id='<flowid>', "
            "client_id='<host_id>', "
            "artifact='Custom.CybORG.Generic.RunClientCommand')}, "
            "b={select * from source("
            "flow_id='<flowid>', "
            "client_id='<host_id>', "
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
