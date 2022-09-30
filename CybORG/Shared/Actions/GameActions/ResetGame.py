# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from .GameAction import GameAction


class ResetGame(GameAction):
    """Resets the game. """

    def emu_execute(self, game_controller, *args, **kwargs) -> Observation:
        # this is a special action in that it's emu_execute function is not
        # called. Instead the emulatorservercontroller will handle the reset
        # logic when it recieves this action.
        # This is done since resetting is a bit different to a normal action
        # and has to handle returning the observation and action space for
        # multiple agents
        assert False
