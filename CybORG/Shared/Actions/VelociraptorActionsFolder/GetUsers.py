# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation
from CybORG.Shared.Enums import OperatingSystemType as ost
from .VelociraptorArtifactAction import VelociraptorArtifactAction


class GetUsers(VelociraptorArtifactAction):
    """Gets the list of users on a host"""

    def __init__(self, session: int, agent: str, ostype: ost, hostname: str = None):

        if ostype == ost.WINDOWS:

            super().__init__(session=session,
                             hostname=hostname,
                             agent=agent,
                             artifact='Windows.Sys.Users',
                             env={},
                             flow_completion_wait_limit=90)

        elif ostype == ost.LINUX:

            super().__init__(session=session,
                             hostname=hostname,
                             agent=agent,
                             artifact='Linux.Sys.Users',
                             env={},
                             flow_completion_wait_limit=90)

        else:

            self.error(f"Unable to handle os type {ostype}")

    def sim_execute(self, state):
        raise NotImplementedError

    def parse(self, results: list, client_id: str) -> Observation:
        """Parses the results of the execute action to create an observation"""
        obs = Observation()

        if results == []:
            obs.set_success(False)
            return obs
        else:
            obs.set_success(True)

        obs.add_system_info(hostid='0', hostname=self.hostname)

        # The result is a dict with the details of the Flow that resulted from the query
        # Given the query is asynchronous, the result will need to be retrieved using
        # a flow completion query

        if 'User' in results[0]:
            for u in results:
                obs.add_user_info(hostid='0', username=u['User'])
        else:
            for u in results:
                obs.add_user_info(hostid='0', username=u['Name'])

        return obs
