from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.State import State


class FloodBandwidth(RemoteAction):
    """Sends a large amount of junk data to consume bandwidth"""
    def __init__(self, session: int, agent: str, ip_address: IPv4Address):
        super(FloodBandwidth, self).__init__(session, agent)
        self.ip_address = ip_address
        self.bandwidth_usage = 100

    def get_used_route(self, state: State) -> list:
        """finds the route used by the action and returns the hostnames along that route"""
        return self.get_route(state, state.ip_addresses[self.ip_address], state.sessions[self.agent][self.session].hostname)

    def execute(self, state: State) -> Observation:
        if self.session in state.sessions[self.agent]:
            route = self.get_used_route(state)
            if route is not None:
                hostname = state.sessions[self.agent][self.session].hostname
                for other_hostname in route:
                    host = state.hosts[other_hostname]
                    event = {
                        'local_address': self.ip_address,
                        'remote_port': 8888,
                        'remote_address': {h_name: ip_addr for ip_addr, h_name in state.ip_addresses.items()}[hostname]
                    }
                    host.events['NetworkConnections'].append(event)
                    if other_hostname == self.blocked:
                        break
                return Observation(True)
            else:
                return Observation(False)
        else:
            return Observation(False)
