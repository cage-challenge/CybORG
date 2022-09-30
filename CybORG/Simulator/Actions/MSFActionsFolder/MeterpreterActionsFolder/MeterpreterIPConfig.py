# Copyright DST Group. Licensed under the MIT license.
import re
from ipaddress import IPv4Network

from CybORG.Simulator.Actions.MSFActionsFolder.MeterpreterActionsFolder.MeterpreterAction import MeterpreterAction
from CybORG.Shared.Enums import OperatingSystemType, SessionType
from CybORG.Shared.Observation import Observation


class MeterpreterIPConfig(MeterpreterAction):
    def __init__(self, session, agent, target_session):
        super().__init__(session, agent, target_session)

    def execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent] or state.sessions[self.agent][self.session].session_type != SessionType.MSF_SERVER:
            return obs
        if self.meterpreter_session not in state.sessions[self.agent] or state.sessions[self.agent][self.meterpreter_session].session_type != SessionType.METERPRETER:
            return obs
        if state.sessions[self.agent][self.session].active and state.sessions[self.agent][self.meterpreter_session].active:
            host = state.hosts[state.sessions[self.agent][self.meterpreter_session].hostname]
            obs.set_success(True)
            for interface in host.interfaces:
                obs.add_interface_info(hostid=str(self.meterpreter_session), **(interface.get_state()))
        return obs


    def _format_log_msg(self, msg):
        return f"{self.__class__.__name__} : {msg} "