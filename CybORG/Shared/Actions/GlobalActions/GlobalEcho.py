# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from CybORG.Emulator.EmulatorCLIManager import EmulatorCLIManager

from .GlobalAction import GlobalAction


class GlobalEcho(GlobalAction):

    def __init__(self, echo_cmd):
        super().__init__()
        self.cmd = echo_cmd

    def emu_execute(self, team_server) -> Observation:
        cli = EmulatorCLIManager()
        cmd = f"echo {self.cmd}"
        output = cli.execute_command(cmd)
        obs = Observation()
        obs.set_success(True)
        obs.add_raw_obs(output)
        return obs
