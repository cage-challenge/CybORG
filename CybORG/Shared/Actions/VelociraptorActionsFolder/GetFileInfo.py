# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Observation import Observation
from CybORG.Shared.Enums import SessionType, QueryType

from .VelociraptorAction import VelociraptorAction


class GetFileInfo(VelociraptorAction):

    def __init__(self, session: int, agent: str):
        super().__init__(session=session,
                         query_type=QueryType.ASYNC,
                         agent=agent)
        self.agent = agent

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.VELOCIRAPTOR_CLIENT:
            return obs

        obs.set_success(True)

        users = {}

        for file in session.host.files:
            try:
                user = file.user.username
            except Exception:
                pass

            group = file.group
            if user not in users.keys():
                users[user] = [group]
            elif group not in users[user]:
                users[user].append(group)

            obs.add_file_info(
                hostid="0",
                name=file.name,
                path=file.path,
                group=file.group,
                group_permissions=file.group_permissions,
                user=file.user.username,
                user_permissions=file.user_permissionss,
                default_permissions=file.default_permissions,
                file_type=file.file_type,
                version=file.version,
                vendor=file.vendor,
                last_modified_time=file.last_modified_time
            )

        for user, groups in users.items():
            for group in groups:
                obs.add_user_info(hostid="0", username=user, group_name=group)

        return obs
