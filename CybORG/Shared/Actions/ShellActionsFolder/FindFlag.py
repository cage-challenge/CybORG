# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.ShellAction import ShellAction
from CybORG.Shared.Enums import FileType
from CybORG.Shared.Observation import Observation


class FindFlag(ShellAction):

    def __init__(self, session, agent):
        super().__init__(session, agent)

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs

        session = state.sessions[self.agent][self.session]
        if not session.active:
            return obs

        for file in session.host.files:
            if file.file_type == FileType.FLAG:
                if file.check_readable(session.user):
                    obs.set_success(True)
                    obs.add_file_info(hostid="hostid0", path=file.path, name=file.name, file_type=file.file_type)
                    return obs

        return obs
