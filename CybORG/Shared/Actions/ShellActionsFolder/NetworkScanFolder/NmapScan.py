# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address, IPv4Network

from CybORG.Shared.Actions.ShellActionsFolder.NetworkScanFolder.NetworkScan import NetworkScan
from CybORG.Shared.Enums import FileType, InterfaceType
from CybORG.Shared.Observation import Observation


class NmapScan(NetworkScan):
    def __init__(self, session, agent, subnet):
        super().__init__(session, agent, subnet)

    def sim_execute(self, state):
        obs = Observation()
        obs.set_success(False)
        if self.session not in state.sessions[self.agent]:
            return obs

        subnet = state.subnets[self.subnet]
        from_host = state.sessions[self.agent][self.session].host

        if not state.sessions[self.agent][self.session].active:
            obs.set_success(False)
            return obs

        good = False
        for file in from_host.files:
            if file.file_type == FileType.NMAP:
                if file.check_executable(state.sessions[self.agent][self.session].user):
                    good = True
                    break

        if not good:
            obs.set_success(False)
            return obs

        good = False
        for interface in from_host.interfaces:
            if self.subnet == interface.subnet:
                good = True
                break

        if not good:
            obs.set_success(False)
            return obs

        for ip_address in subnet.ip_addresses:
            if state.ip_addresses[ip_address].respond_to_ping:
                obs.add_interface_info(hostid=ip_address, ip_address=ip_address, subnet=self.subnet)
                obs.set_success(True)
                # iterate through processes to find ports listening on this or all interfaces
            for process in state.ip_addresses[ip_address].processes:
                obs.set_success(True)
                for conn in process.connections:
                    if conn['local_address'] == IPv4Address("0.0.0.0") or (conn['local_address'] in self.subnet.hosts() and 'remote_address' not in conn):
                        obs.add_process(hostid=ip_address, local_address=ip_address, local_port=conn['local_port'], app_protocol=conn['Application Protocol'], status='open')

        return obs
