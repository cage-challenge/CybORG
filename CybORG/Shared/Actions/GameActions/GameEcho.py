# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from .GameAction import GameAction

from CybORG.Emulator.EmulatorCLIManager import EmulatorCLIManager


class GameEcho(GameAction):

    def __init__(self, echo_cmd: str):
        super().__init__()
        self.cmd = echo_cmd

    def emu_execute(self, game_controller, *args, **kwargs) -> Observation:
        cli = EmulatorCLIManager()
        cmd = f"echo {self.cmd}"
        output = cli.execute_command(cmd)
        obs = Observation()
        obs.set_success(True)
        obs.add_raw_obs(output)
        return obs
