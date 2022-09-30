# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Enums import QueryType
from CybORG.Shared.Observation import Observation

from .VelociraptorAction import VelociraptorAction


class GetLocalGroups(VelociraptorAction):

    def __init__(self, session: int, agent: str):
        super().__init__(session=session,
                         query_type=QueryType.ASYNC,
                         tag=agent)
        self.agent = agent

    def sim_execute(self, state):
        obs = Observation()
        return obs
