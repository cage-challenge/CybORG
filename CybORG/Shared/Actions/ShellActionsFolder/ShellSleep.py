# Copyright DST Group. Licensed under the MIT license.

import time

from CybORG.Shared import Observation

from .ShellAction import ShellAction


class ShellSleep(ShellAction):

    def __init__(self,
                 session: int = None,
                 agent: str = None,
                 t: int = 1):
        super().__init__(session, agent)
        self.t = t

    def sim_execute(self, state):
        return Observation()

    def emu_execute(self, session_handler):
        time.sleep(self.t)
        obs = Observation()
        obs.add_raw_obs(f"I slept {self.t} secs")
        return obs
