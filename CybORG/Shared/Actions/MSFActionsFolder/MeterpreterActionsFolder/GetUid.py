# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.MSFActionsFolder.MeterpreterActionsFolder.MeterpreterAction import MeterpreterAction
from CybORG.Shared.Enums import SessionType, OperatingSystemType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# Call getuid from a meterpreter session - gives the username of the session
class GetUid(MeterpreterAction):
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session=session, agent=agent, target_session=target_session)

    def sim_execute(self, state: State):
        obs = Observation()
        obs.set_success(False)

        if self.session not in state.sessions[self.agent] or state.sessions[self.agent][
            self.session].session_type != SessionType.MSF_SERVER:
            return obs
        if self.meterpreter_session not in state.sessions[self.agent] or state.sessions[self.agent][
            self.meterpreter_session].session_type != SessionType.METERPRETER:
            return obs
        if state.sessions[self.agent][self.session].active and state.sessions[self.agent][self.meterpreter_session].active:
            obs.set_success(True)
            obs.add_user_info(username=state.sessions[self.agent][self.meterpreter_session].username)
        return obs
