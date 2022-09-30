# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from .AgentAction import AgentAction


class ListSessions(AgentAction):
    """Get IDs of all active sessions for an agent. """

    def emu_execute(self, agent, *args, **kwargs) -> Observation:
        session_ids = agent.list_sessions()
        obs = Observation()
        obs.set_success(True)
        obs.add_key_value("session_ids", session_ids)
        return obs
