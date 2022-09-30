# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from .GameAction import GameAction


class ListAllSessions(GameAction):
    """Get session info for all active sessions for all agents for a game.
    """

    def emu_execute(self, game_controller, *args, **kwargs) -> Observation:
        obs = Observation()
        for agent in game_controller.list_agents():
            agent_controller = game_controller.get_agent(agent)
            for session in agent_controller.list_sessions():
                session_controller = agent_controller.get_session(session)
                obs.add_session_info(
                    agent=agent,
                    **session_controller.get_info()
                )
        obs.set_success(True)
        return obs
