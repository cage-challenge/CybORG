# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.ShellActionsFolder.NetworkScanFolder.NetworkScan import NetworkScan
from CybORG.Shared.Observation import Observation


class PingSweep(NetworkScan):
    def __init__(self, session, subnet, agent):
        super().__init__(session, agent, subnet)

    def sim_execute(self, state):
        obs = Observation()
        if self.session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs

        if self.subnet in state.subnets:
            subnet = state.subnets[self.subnet]
        else:
            return obs
        from_host = state.sessions[self.agent][self.session].host

        if not state.sessions[self.agent][self.session].active:
            obs.set_success(False)
            return obs

        good = False
        from_interface = None
        for interface in from_host.interfaces:
            if self.subnet == interface.subnet:
                good = True
                break

        if not good:
            return obs

        for ip_address in subnet.ip_addresses:
            if state.ip_addresses[ip_address].respond_to_ping:
                obs.add_interface_info(ip_address=ip_address, subnet=self.subnet)

        return obs