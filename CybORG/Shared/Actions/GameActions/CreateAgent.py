# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from .GameAction import GameAction


class CreateAgent(GameAction):
    """Create a new agent on Team server for given game. """

    def __init__(self, agent_name: str):
        """
        Parameters
        ----------
        agent_name : str
            the name of agent in the scenario file
        """
        super().__init__()
        self.agent_name = agent_name

    def emu_execute(self, game_controller, *args, **kwargs) -> Observation:
        return game_controller.add_agent(self.agent_name)

    def __str__(self):
        return (f"{self.__class__.__name__}: "
                f"Agent Name:{self.agent_name}")
