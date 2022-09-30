from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ExploitAction import ExploitAction
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process
from CybORG.Simulator.State import State


class SQLInjection(ExploitAction):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address, target_session: int):
        super().__init__(session, agent, ip_address, target_session)

    def sim_execute(self, state: State) -> Observation:
        return self.sim_exploit(state, 3390, 'mysql')

    def test_exploit_works(self, target_host: Host, vuln_proc: Process):
        # ask Max on what properties to check
        return bool(True)
