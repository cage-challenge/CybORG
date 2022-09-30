from ipaddress import IPv4Address

from numpy import True_

from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ExploitAction import ExploitAction
from CybORG.Shared.Enums import ProcessVersion
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process
from CybORG.Simulator.State import State


class HarakaRCE(ExploitAction):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address, target_session: int):
        super().__init__(session, agent, ip_address, target_session)

    def sim_execute(self, state: State) -> Observation:
        return self.sim_exploit(state, 25, 'smtp')

    def test_exploit_works(self, target_host: Host, vuln_proc: Process):        
        # make sure the Haraka version < 2.8.9        
        return vuln_proc.version.value < ProcessVersion.HARAKA_2_8_9.value
