# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.MSFActionsFolder.MeterpreterActionsFolder.MeterpreterAction import MeterpreterAction
from CybORG.Shared.Enums import OperatingSystemType, SessionType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# Call getpid from a meterpreter session - gives the process id of the session
class GetPid(MeterpreterAction):
    def __init__(self, session: int, agent: str):
        super().__init__(session=session, agent=agent)

    def sim_execute(self, state: State):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.METERPRETER or not session.active:
            return obs

        if session.host.os_type == OperatingSystemType.LINUX:
            for group in session.user.groups:
                # Is this the best way to check this? Can group name be changed, is there some other way to check if it
                # is a user with minimal privileges?
                if group.name == "nogroup":
                    return obs

        obs.set_success(True)
        obs.add_session_info(session_id=self.session, agent=self.agent, pid=session.process.pid,
                             session_type="meterpreter")
        return obs
