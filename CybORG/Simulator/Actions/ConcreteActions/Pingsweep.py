from ipaddress import IPv4Network

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.Actions.ConcreteActions.LocalAction import LocalAction
from CybORG.Simulator.Actions.Action import lo_subnet, lo
from CybORG.Simulator.State import State


class Pingsweep(RemoteAction):
    """
    Concrete action that simulates a pingsweep, returning a list of active ip addresses on a subnet.
    """
    def __init__(self, session: int, agent: str, subnet: IPv4Network):
        super().__init__(session, agent)
        
        self.subnet = subnet

    def get_used_route(self, state: State) -> list:
        """finds the route used by the action and returns the hostnames along that route"""
        routes = [set(self.get_route(state, state.ip_addresses[ip_address], state.sessions[self.agent][self.session].hostname)) for ip_address in state.subnets[self.subnet].ip_addresses]
        route = []
        for r in routes:
            route += r
        return list(route)

    def execute(self, state: State) -> Observation:
        """
        Executes a pingsweep in the simulator.
        """
        obs = Observation()

        # Check the session running the code exists and is active.
        if self.session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        from_host = state.hosts[state.sessions[self.agent][self.session].hostname]
        session = state.sessions[self.agent][self.session]
        if not session.active:
            obs.set_success(False)
            return obs

        # Collect ip addresses
        if self.subnet == lo_subnet:
            # Loopback address triviality
            obs.set_success(True)
            obs.add_interface_info(hostid=str(lo_subnet), subnet=lo_subnet, ip_address=lo)
        else:
            # Check that a route exists to each ip that exists in the subnet
            for ip_addr in state.subnets[self.subnet].ip_addresses:
                if state.hosts[state.ip_addresses[ip_addr]].respond_to_ping:
                    from_ip = self._get_originating_ip(state, from_host, ip_addr)
                    if from_ip is not None:
                        obs.set_success(True)
                        obs.add_interface_info(hostid=str(ip_addr), ip_address=ip_addr, subnet=self.subnet)
        return obs
