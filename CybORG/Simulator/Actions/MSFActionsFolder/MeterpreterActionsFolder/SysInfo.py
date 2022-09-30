# Copyright DST Group. Licensed under the MIT license.
from CybORG.Simulator.Actions.MSFActionsFolder.MeterpreterActionsFolder.MeterpreterAction import MeterpreterAction
from CybORG.Shared.Enums import OperatingSystemType, SessionType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# Call sysinfo from a meterpreter session - gives internal system information
class SysInfo(MeterpreterAction):
    def __init__(self, session: int, agent: str):
        super().__init__(session=session, agent=agent)

    def execute(self, state: State):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs
        session = state.sessions[self.agent][self.session]

        if session.session_type != SessionType.METERPRETER or not session.active:
            return obs

        obs.set_success(True)

        if session.hostname.os_type == OperatingSystemType.LINUX:
            for group in session.user.groups:
                # Is this the best way to check this? Can group name be changed, is there some other way to check if it
                # is a user with minimal privileges?
                if group.name == "nogroup":
                    obs.add_system_info(hostname=session.hostname.hostname, os_type=OperatingSystemType.LINUX,
                                        os_kernel=session.hostname.kernel, architecture=session.hostname.architecture)
                    return obs
            obs.add_system_info(hostname=session.hostname.hostname, os_type=OperatingSystemType.LINUX,
                                os_distribution=session.hostname.distribution, os_version=session.hostname.version,
                                os_kernel=session.hostname.kernel, architecture=session.hostname.architecture)
            return obs
        else:
            obs.add_system_info(hostname=session.hostname.hostname, os_type=session.hostname.os_type,
                                os_distribution=session.hostname.distribution, os_version=session.hostname.version,
                                architecture=session.hostname.architecture)
            return obs
