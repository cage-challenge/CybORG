# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation
from CybORG.Shared.Actions import SessionAction


class LocalShellEcho(SessionAction):

    def __init__(self, session: int, echo_cmd: str = "Hello, World!"):
        super().__init__(session)
        self.cmd = echo_cmd

    def emu_execute(self, session_handler, *args, **kwargs):
        cmd = f"echo {self.cmd}"
        output = session_handler.execute(cmd)
        obs = Observation()
        obs.set_success(True)
        obs.add_raw_obs(output)
        return obs
