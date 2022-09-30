# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation

from .VelociraptorAction import VelociraptorAction


class GetUserInfo(VelociraptorAction):
    """Gets information about a user"""

    def __init__(self, session: int, agent: str, hostname: str, username: str):
        super().__init__(session=session,
                         query_type=QueryType.ASYNC,
                         agent=agent)
        self.agent = agent
        self.hostname = hostname
        self.username = username
        self.parameters['artifactname'] = 'Custom.Wrappered.*.Sys.Users'
        self.query = (
            "select collect_client("
            "client_id='<host_id>', "
            "artifacts=['Custom.Wrappered.Windows.Sys.Users', "
            "'Custom.Wrappered.Linux.Sys.Users'], "
            "env=dict(agentid='<agentid>', "
            "artifactname='<artifactname>', "
            "tag='<tag>'))"
            " FROM scope()"
        )
        self.source_query = (
            "select * from chain("
            "a={select Name, Uid, Gid from source("
            "flow_id='<flowid>', "
            "client_id='<host_id>', "
            "artifact='Custom.Wrappered.Windows.Sys.Users') "
            "where Name='<username>'}, "
            "b={select User, Uid, Gid from source("
            "flow_id='<flowid>', "
            "client_id='<host_id>', "
            "artifact='Custom.Wrappered.Linux.Sys.Users') "
            "where User='<username>'})"
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

        user_data = results[0]
        if 'User' in user_data:
            obs.add_user_info(
                hostid='0',
                username=user_data['User'],
                uid=user_data['Uid'],
                gid=user_data['Gid']
            )
        else:
            obs.add_user_info(
                hostid='0',
                username=user_data['Name'],
                uid=user_data['Uid'],
                gid=user_data['Gid']
            )
        return obs
