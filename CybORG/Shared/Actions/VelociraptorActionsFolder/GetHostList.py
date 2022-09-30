# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation

from .VelociraptorAction import VelociraptorAction


class GetHostList(VelociraptorAction):
    """Get a list of all hosts being monitored"""

    def __init__(self, session: int, agent: str):
        super().__init__(session=session,
                         agent=agent,
                         query_type=QueryType.SYNC)
        self.parameters['tag'] = 'internal_query'
        self.parameters['artifactname'] = 'GetHostList'
        self.query = "SELECT client_id, os_info.fqdn FROM clients()"

    def sim_execute(self, state):
        raise NotImplementedError

    def parse(self, results: list, client_id: str) -> Observation:
        """Parses the results of the execute action to create an observation"""
        obs = Observation()
        if results == []:
            obs.set_success(False)
            return obs
        else:
            obs.add_raw_obs(results)
            obs.set_success(True)
        for host in results:
            obs.add_system_info(
                hostid=host["client_id"],
                hostname=host['os_info.fqdn']
            )
        return obs
