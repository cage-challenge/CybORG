# These tests check that the green actions are working:
# DiscoverRemoteSystems, DiscoverNetworkServices, ExploitService, Escalate, Impact

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently
from ipaddress import IPv4Network, IPv4Address

from docutils.nodes import address

from CybORG import CybORG
import inspect
import pytest

from CybORG.Shared.Actions import Sleep
from CybORG.Shared.Actions.GreenActions.GreenConnection import GreenConnection
from CybORG.Shared.Actions.AbstractActions.Monitor import Monitor
from CybORG.Agents.SimpleAgents.BlueMonitorAgent import BlueMonitorAgent

from CybORG.Shared.Enums import TrinaryEnum, OperatingSystemVersion, OperatingSystemType, OperatingSystemDistribution, \
    Architecture
from CybORG.Tests.EphemeralPort import LinuxEphemeralPort


@pytest.mark.skip("Not implemented")
def test_GreenConnection():
    # Create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim',agents={'Blue':BlueMonitorAgent})

    # Test GreenConnection
    session = 0
    action = GreenConnection(agent='Green', session=session, hostname='User3')
    _ = cyborg.step(action=action, agent='Green')
    _ = cyborg.step(action=action, agent='Green')
    blue_obs = cyborg.get_observation('Blue')
                                                                         
    address = cyborg.get_ip_map()['User3']
    attacker_address = cyborg.environment_controller.hostname_ip_map['User0']
    expected_observation = {'Enterprise0': {'Interface': [{'IP Address': address}],
                                            'Processes': [{'Connections': [{'local_address': address,
                                                                            'local_port': 22,
                                                                            'remote_address': attacker_address,
                                                                            'remote_port': LinuxEphemeralPort()}]}
                                                          for i in range(11)],
   'System info': {'Architecture': Architecture.x64,
                   'Hostname': 'Enterprise0',
                   'OSDistribution': OperatingSystemDistribution.UBUNTU,
                   'OSType': OperatingSystemType.LINUX,
                   'OSVersion': OperatingSystemVersion.U18_04_3}},
                            'success': TrinaryEnum.TRUE}

    assert blue_obs == expected_observation

