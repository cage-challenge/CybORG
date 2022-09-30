# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Network

from CybORG.Shared.Actions.MSFActionsFolder.MSFAction import MSFAction
from CybORG.Shared.Enums import SessionType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


class MSFAutoroute(MSFAction):
    def __init__(self, target_session, agent, session):
        super().__init__(session, agent)
        self.meterpreter_session = target_session

    def sim_execute(self, state: State):
        obs = Observation()
        if self.session not in state.sessions[self.agent] or self.meterpreter_session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        interfaces = []
        meterpreter_session = state.sessions[self.agent][self.meterpreter_session]
        msf_session = state.sessions[self.agent][self.session]
        if meterpreter_session in msf_session.children.values() and meterpreter_session.session_type == SessionType.METERPRETER and msf_session.session_type == SessionType.MSF_SERVER:
            obs.set_success(True)
            for interface in state.hosts[meterpreter_session.host].interfaces:
                if str(interface.ip_address) != '127.0.0.1':
                    interfaces.append(interface)
                    obs.add_interface_info(hostid=str(self.meterpreter_session), subnet=interface.subnet)
            msf_session.routes[self.meterpreter_session] = interfaces
        else:
            obs.set_success(False)
        return obs

    def emu_execute(self, session_handler) -> Observation:
        obs = Observation()
        from CybORG.Emulator.Session import MSFSessionHandler
        if type(session_handler) is not MSFSessionHandler:
            obs.set_success(False)
            return obs
        output = session_handler.execute_module(mtype='post', mname='multi/manage/autoroute',
                                         opts={'SESSION': self.meterpreter_session})
        obs.add_raw_obs(output)
        """Example:
        [!] SESSION may not be compatible with this module.
        [*] Running module against 10.0.2.164
        [*] Searching for subnets to autoroute.
        [+] Route added to subnet 10.0.2.0/255.255.254.0 from host's routing table.
        [*] Post module execution completed
        """
        obs.set_success(False)
        for line in output.split('\n'):
            if '[+] Route added' in line:
                obs.set_success(True)
                subnet = line.split(' ')[5]
                obs.add_interface_info(hostid=str(self.meterpreter_session), subnet=IPv4Network(subnet))

        return obs

    def __str__(self):
        return super(MSFAutoroute, self).__str__() + f", Meterpreter Session: {self.meterpreter_session}"
