# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared.Observation import Observation
from CybORG.Shared.Enums import SessionType, QueryType

from .. import Action


class VelociraptorPoll(Action):

    def __init__(self, session: int, agent: str):
        super().__init__(session=session,
                         agent=agent,
                         query_type=QueryType.SYNC,
                         poll_alerts=True)

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.VELOCIRAPTOR_SERVER:
            return obs

        obs = state.get_true_state()
        obs.set_success(True)
        # remove hosts without a velociraptor client or server from obs
        for hostname, host in state.hosts.items():
            client = False
            # need to check if key self.agent exists in dict.sessions first
            if self.agent in host.sessions:
                for session in host.sessions[self.agent]:
                    s_type = session.session_type
                    if s_type == SessionType.VELOCIRAPTOR_CLIENT \
                       or s_type == SessionType.VELOCIRAPTOR_SERVER:
                        client = True
                        break
            if not client:
                obs.data.pop(hostname)

        # remember to remove red sessions from white obs
        for host, hostinfo in obs.get_dict().items():
            if host != "success":
                for session in hostinfo["Sessions"]:
                    if session["Agent"] != self.agent:
                        hostinfo["Sessions"].remove(session)
        return obs
