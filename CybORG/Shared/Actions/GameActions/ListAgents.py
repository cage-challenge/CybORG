# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from .GameAction import GameAction


class ListAgents(GameAction):
    """List all active agents for given game.
    """

    def emu_execute(self, game_controller, *args, **kwargs) -> Observation:
        agent_ids = game_controller.list_agents()
        obs = Observation()
        obs.set_success(True)
        obs.add_key_value("agent_ids", agent_ids)
        return obs
