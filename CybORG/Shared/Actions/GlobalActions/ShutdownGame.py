# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared import Observation

from .GlobalAction import GlobalAction


class ShutdownGame(GlobalAction):
    """Shutdown a game. """

    def __init__(self, game_id: int, teardown: bool = True):
        """
        Parameters
        ----------
        game_id : int
            ID of game to shutdown
        teardown : bool, optional
            whether to terminate network resources or not (default=True)
        """
        super().__init__()
        self.game_id = game_id
        self.teardown = teardown

    def emu_execute(self, team_server, *args, **kwargs) -> Observation:
        obs = Observation()
        success = team_server.shutdown_game(self.game_id, self.teardown)
        obs.set_success(success)
        return obs
