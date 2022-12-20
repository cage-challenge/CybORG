from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.ConcreteActions.LocalAction import LocalAction
from CybORG.Simulator.State import State


class BlockTraffic(LocalAction):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address):
        super(BlockTraffic, self).__init__(session, agent)
        self.ip_address = ip_address
        self.priority = 1

    def execute(self, state: State) -> Observation:
        if self.agent in state.sessions and self.session in state.sessions[self.agent] and state.sessions[self.agent][self.session].active:
            hostname = state.sessions[self.agent][self.session].hostname
        else:
            return Observation(False)
        other_hostname = state.ip_addresses[self.ip_address]
        if hostname in state.blocks:
            if other_hostname not in state.blocks[hostname]:
                state.blocks[hostname].append(other_hostname)
            else:
                return Observation(False)
        else:
            state.blocks[hostname] = [other_hostname]
        return Observation(True)

class AllowTraffic(LocalAction):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address):
        super(AllowTraffic, self).__init__(session, agent)
        self.ip_address = ip_address
        self.priority = 1

    def execute(self, state: State) -> Observation:
        if self.agent in state.sessions and self.session in state.sessions[self.agent] and state.sessions[self.agent][self.session].active:
            hostname = state.sessions[self.agent][self.session].hostname
        else:
            return Observation(False)
        other_hostname = state.ip_addresses[self.ip_address]
        if hostname in state.blocks:
            if other_hostname in state.blocks[hostname]:
                state.blocks[hostname].remove(other_hostname)
                return Observation(True)
        return Observation(False)
