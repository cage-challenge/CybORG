# These tests check that the green actions are working:
# DiscoverRemoteSystems, DiscoverNetworkServices, ExploitService, Escalate, Impact

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently
from ipaddress import IPv4Network, IPv4Address

from CybORG import CybORG
import inspect

from CybORG.Shared.Actions.GreenActions.GreenPortScan import GreenPortScan
from CybORG.Shared.Actions import Monitor
from CybORG.Agents.SimpleAgents.BlueMonitorAgent import BlueMonitorAgent

from CybORG.Shared.Enums import TrinaryEnum, ProcessType, ProcessState, SessionType, OperatingSystemType, OperatingSystemDistribution, OperatingSystemVersion, Architecture
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort
import pytest

def process_connections(obs, local_address, remote_address, ports):
    # Don't know how to get expected remote port, so use this function to compare other data
    assert 'User2' in obs
    host = obs['User2']
    assert 'Processes' in host
    proc_list = host['Processes']
    port_set = set()
    for process in proc_list:
        assert 'Connections' in process
        conn_list = process['Connections']
        assert len(conn_list) == 1
        connection = conn_list[0]
        assert 'local_port' in connection
        port_set.add(connection['local_port'])
        assert 'local_address' in connection
        assert connection['local_address'] == local_address
        assert 'remote_address' in connection
        assert connection['remote_address'] == remote_address
    assert port_set == ports

def test_GreenPortScan():
    # Create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim',agents={'Blue':BlueMonitorAgent})

    # Setup Agent
    for i in range(2):
        action = GreenPortScan(session=0,agent='Green',hostname='User2')
        results = cyborg.step('Green', action)                   

    obs = cyborg.get_observation('Blue')
                                                                         
    local_address = cyborg.environment_controller.hostname_ip_map['User2']
    remote_address = cyborg.environment_controller.hostname_ip_map['User0']
    ports = set([135,3389,445,139])

    process_connections(obs,local_address,remote_address,ports)
