import warnings
from ipaddress import IPv4Address

from gym.utils import seeding

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.State import State


class SendData(RemoteAction):
    """Sends some specific data to another host"""
    def __init__(self, session: int, agent: str, ip_address: IPv4Address, bandwidth_usage: float):
        super(SendData, self).__init__(session, agent)
        self.ip_address = ip_address
        self.bandwidth_usage = bandwidth_usage
        self.detection_rate = 0.05
        self.blocked = False

    def get_used_route(self, state: State) -> list:
        """finds the route used by the action and returns the hostnames along that route"""
        return self.get_route(state, state.ip_addresses[self.ip_address], state.sessions[self.agent][self.session].hostname)

    def execute(self, state: State) -> Observation:
        obs = Observation(False)
        hostname = state.sessions[self.agent][self.session].hostname
        if not self.dropped:
            route = self.get_used_route(state)

            for other_hostname in route:
                # Get host object for corresponding hostname
                host = state.hosts[other_hostname]
                # Get the list of agents mapped to sessions for the host
                host_agents = host.sessions.keys()
                # Iterate through list of agents operating session
                for agent in host_agents:
                    # Check that agent's team name contains 'red', assume modification if true
                    if 'red' in agent.lower():
                        # Iterate through list of session objects under agent
                        for session in host.sessions[agent]:
                            # Check if agent has escalated privileges within session
                            if state.sessions[agent][session].username == 'root' or state.sessions[agent][session].username == 'SYSTEM':
                                return obs
                if other_hostname == self.blocked:
                    event = {
                        'local_address': self.ip_address,
                        'remote_port': 8888,
                        'remote_address': {h_name: ip_addr for ip_addr, h_name in state.ip_addresses.items()}[hostname]
                    }
                    host.events['NetworkConnections'].append(event)
                    return obs
                elif state.np_random.random() < self.detection_rate:
                    # add even to hosts along the path if detection occurs
                    event = {
                        'local_address': self.ip_address,
                        'remote_port': 8888,
                        'remote_address': {h_name: ip_addr for ip_addr, h_name in state.ip_addresses.items()}[hostname]
                    }
                    host.events['NetworkConnections'].append(event)
        else:
            return obs
        return Observation(True)
