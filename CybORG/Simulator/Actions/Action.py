# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address, IPv4Network
from typing import Optional

from networkx import shortest_path, has_path, NetworkXNoPath

from CybORG.Shared import Observation, CybORGLogger
from CybORG.Simulator.Host import Host
from CybORG.Simulator.State import State

lo_subnet = IPv4Network('127.0.0.0/8')
lo = IPv4Address('127.0.0.1')

class Action(CybORGLogger):

    def __init__(self):
        self.name = self.__class__.__name__
        self.priority = 99

    def execute(self, state: State) -> Observation:
        raise NotImplementedError(f'Action {type(self)} not implemented')

    def check_c2(self, state: State, session: int) -> bool:
        return True

    def __str__(self):
        return f"{self.__class__.__name__}"

    def __repr__(self):
        return self.__str__()

    def get_params(self) -> dict:
        return {key: value for key, value in self.__dict__.items() if not key.startswith('__') and not callable(key)}

    @property
    def cost(self):
        return 0


class Sleep(Action):
    def execute(self, state):
        return Observation()

class InvalidAction(Action):

    def __init__(self, action: Action = None, error: str =None):
        super().__init__()
        self.action = action
        self.error = error

    def execute(self, state):
        return Observation(success=False)

    @property
    def cost(self):
        return -0.1

class RemoteAction(Action):

    def __init__(self, session: int, agent: str):
        super(RemoteAction, self).__init__()
        self.agent = agent
        self.session = session
        self.dropped = False
        self.blocked = False
        self.bandwidth_usage = 0


    @staticmethod
    def get_route(state: State, target: str, source: str) -> list:
        """finds the route from one ip_address to another and returns the hostname list along that route"""
        try:
            path = shortest_path(state.link_diagram, source=source, target=target)
        except NetworkXNoPath:
            path = None
        return path

    def get_used_route(self, state: State) -> list:
        """finds the route used by the action and returns the hostnames along that route"""
        raise NotImplementedError

    @staticmethod
    def check_routable(state: State, target: str, source: str) -> bool:
        """
        Checks if data can be send from one address to another
        """
        for connected_components in state.connected_components:
            if source in connected_components:
                return target in connected_components

    def _get_originating_ip(self, state: State, from_host: Host, target_ip_address) -> Optional[IPv4Address]:
        """
        finds the ip address capable of sending data to the target address

            Parameters
            ----------
            state : State
                the current state of the simulation
            from_host : Host
                the host that is attempting to send data to the target IP address
            target_ip_address : IPv4Address
                the target IP address to which a route is being looked for
            Returns
            -------
            IPv4Address
                the IP address from which data can be sent to the target address else returns None if no route exists
        """
        if from_host is None:
            return None

        originating_ip_address = None
        if target_ip_address == lo:
            return target_ip_address
        else:
            # hacky fix to enable operational firewall in scenario1b and scenario2
            if state.operational_firewall:
                if 'red' in self.agent.lower() and target_ip_address in state.subnet_name_to_cidr['Operational']:
                    bypass_operational_firewall = self.check_for_enterprise_sessions(state)
                    if not bypass_operational_firewall:
                        return None
            route = self.get_route(state, state.ip_addresses[target_ip_address], from_host.hostname)
            if route is None:
                return None
            elif len(route) == 1:
                return target_ip_address
            else:
                for i in from_host.interfaces:
                    if route[1] in i.data_links:
                        return i.ip_address
        return originating_ip_address

    def check_for_enterprise_sessions(self, state):
        """temporary hacky fix for scenario1b and scenario2 oeprational firewall"""
        permission = False
        for session_id in state.sessions[self.agent]:
            session = state.sessions[self.agent][session_id]
            if 'Enterprise' in session.hostname:
                permission = True

        return permission
