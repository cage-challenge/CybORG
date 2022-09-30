# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared import Observation

from .ShellAction import ShellAction


class ShellEcho(ShellAction):

    def __init__(self,
                 session: int = None,
                 agent: str = None,
                 echo_cmd: str = "Testing",
                 **kwargs):
        super().__init__(session, agent)
        self.cmd = echo_cmd

    def sim_execute(self, state):
        return Observation()

    def emu_execute(self, session_handler, *args, **kwargs):
        cmd = f"echo {self.cmd}"
        output = session_handler.execute(cmd)
        obs = Observation()
        obs.set_success(True)
        obs.add_raw_obs(output)
        return obs
