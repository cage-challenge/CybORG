# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Network

from CybORG.Simulator.Actions.MSFActionsFolder.MSFAction import MSFAction
from CybORG.Shared.Enums import SessionType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


class MSFAutoroute(MSFAction):
    def __init__(self, target_session, agent, session):
        super().__init__(session, agent)
        self.meterpreter_session = target_session

    def execute(self, state: State):
        obs = Observation()
        if self.session not in state.sessions[self.agent] or self.meterpreter_session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        interfaces = []
        meterpreter_session = state.sessions[self.agent][self.meterpreter_session]
        msf_session = state.sessions[self.agent][self.session]
        if meterpreter_session in msf_session.children.values() and meterpreter_session.session_type == SessionType.METERPRETER and msf_session.session_type == SessionType.MSF_SERVER:
            obs.set_success(True)
            for interface in state.hosts[meterpreter_session.hostname].interfaces:
                if str(interface.ip_address) != '127.0.0.1':
                    interfaces.append(interface)
                    obs.add_interface_info(hostid=str(self.meterpreter_session), subnet=interface.subnet)
            msf_session.routes[self.meterpreter_session] = interfaces
        else:
            obs.set_success(False)
        return obs


    def __str__(self):
        return super(MSFAutoroute, self).__str__() + f", Meterpreter Session: {self.meterpreter_session}"
