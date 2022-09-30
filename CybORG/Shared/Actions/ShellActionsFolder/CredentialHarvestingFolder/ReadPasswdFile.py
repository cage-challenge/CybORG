# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.CredentialHarvestingFolder.CredentialHarvesting import CredentialHarvesting
from CybORG.Shared.Enums import OperatingSystemType, Path
from CybORG.Shared.Observation import Observation


class ReadPasswdFile(CredentialHarvesting):
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

        if session.host.os_type == OperatingSystemType.WINDOWS:
            obs.add_system_info(hostid="0", os_type="windows")
        elif session.host.os_type == OperatingSystemType.LINUX:
            passwd_file = False
            for file in session.host.files:
                if file.name == "passwd" and Path.parse_string(file.path) == Path.ETC:
                    passwd_file = True
                    break
            if passwd_file:
                obs.set_success(True)
                obs.add_system_info(hostid="0", os_type="linux")
                for user in session.host.users:
                    if user.groups[0].uid == 0:
                        obs.add_user_info(hostid="0", gid=0, group_name="root", uid=user.uid,
                                          username=user.username)
                    else:
                        obs.add_user_info(hostid="0", gid=user.groups[0].uid, uid=user.uid,
                                          username=user.username)
        return obs
