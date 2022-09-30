from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ExploitAction import ExploitAction
from CybORG.Shared.Enums import ProcessVersion, OperatingSystemPatch, OperatingSystemType
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process
from CybORG.Simulator.State import State


class EternalBlue(ExploitAction):
    def __init__(self, session: int, agent: str, ip_address: IPv4Address, target_session: int):
        super().__init__(session, agent, ip_address, target_session)

    def sim_execute(self, state: State) -> Observation:
        return self.sim_exploit(state, 139, 'smb')

    def test_exploit_works(self, target_host: Host, vuln_proc: Process):
        # check if OS and process information is correct for exploit to work
        return target_host.os_type == OperatingSystemType.WINDOWS and OperatingSystemPatch.MS17_010 not in target_host.patches
