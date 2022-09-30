# Copyright DST Group. Licensed under the MIT license.
import time

from CybORG.Shared import Observation
from .AgentAction import AgentAction


class AgentSleep(AgentAction):

    def __init__(self, t: int = 1):
        super().__init__()
        self.t = t

    def sim_execute(self, state):
        return Observation()

    def emu_execute(self, agent, *args, **kwargs) -> Observation:
        time.sleep(self.t)
        obs = Observation()
        obs.set_success(True)
        obs.add_raw_obs(f"I'm feeling refreshed! I slept {self.t} secs")
        return obs
