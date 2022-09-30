# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address, IPv4Network

from CybORG.Simulator.Actions.MSFActionsFolder.MSFScannerFolder.MSFScanner import MSFScanner
from CybORG.Shared.Enums import InterfaceType, SessionType, ProcessType, ProcessVersion, AppProtocol
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.State import State


# msf module is post/multi/gather/ping_sweep
class MSFPingsweep(MSFScanner):
    def __init__(self, subnet: IPv4Network, session: int, agent: str, target_session: int):
        super().__init__(session, agent)
        self.subnet = subnet
        self.target_session = target_session
        self.lo = IPv4Address("127.0.0.1")

    def execute(self, state: State):
        obs = Observation()
        if self.session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        from_host = state.sessions['Red'][self.session].hostname
        session = state.sessions['Red'][self.session]

        if session.session_type != SessionType.MSF_SERVER or not session.active:
            obs.set_success(False)
            return obs

        if self.target_session in state.sessions['Red']:
            target_session = state.sessions['Red'][self.target_session]
        else:
            obs.set_success(False)
            return obs

        if not (target_session.session_type == SessionType.METERPRETER or target_session.session_type == SessionType.MSF_SHELL) or not target_session.active:
            obs.set_success(False)
            return obs

        target_session, from_interface = self.get_local_source_interface(local_session=target_session,
                                                                         remote_address=self.subnet.network_address,
                                                                         state=state)

        if from_interface is None:
            obs.set_success(False)
            return obs
        target_hosts = []
        for host in state.subnets[self.subnet].ip_addresses:
            if state.hosts[state.ip_addresses[host]].respond_to_ping:
                obs.set_success(True)
                target_hosts.append(host)
                obs.add_interface_info(hostid=str(host), ip_address=host, subnet=self.subnet)

        return obs

    def __str__(self):
        return super(MSFPingsweep, self).__str__() + f", Subnet: {self.subnet}, Client Session: {self.target_session}"
