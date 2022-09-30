import pytest 
import itertools 
from copy import deepcopy

from CybORG.Tests.test_sim.sim_fixtures import subnet_scanner, SCENARIOS
from CybORG.Agents.Utils import ObservationWrapper
from CybORG.Simulator.Actions import DiscoverRemoteSystems
from CybORG.Shared.Enums import SessionType, OperatingSystemType, ProcessType, ProcessState, TrinaryEnum
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort

SCENARIO = 'Scenario2'
HOSTS = SCENARIOS[SCENARIO]['Hosts']
SUBNETS = SCENARIOS[SCENARIO]['Subnets']

EXPLOIT_PARAMETERS = ['session', 'agent', 'subnet']

@pytest.fixture(scope='module', params=SUBNETS)
def stop_subnet(request):
    return request.param

@pytest.fixture(scope='module')
def cyborg(stop_subnet):
    return subnet_scanner(SCENARIO, stop_subnet)

@pytest.fixture(scope='module')
def subnet_cidr(stop_subnet, cyborg):
    return cyborg.get_cidr_map()[stop_subnet]

@pytest.fixture(scope='module')
def action(subnet_cidr):
    return DiscoverRemoteSystems(subnet=subnet_cidr, agent='Red', session=0)

@pytest.fixture(scope='module')
def observation(cyborg,  action):
    results = cyborg.step(action=action, agent='Red')

    return ObservationWrapper(results.observation)

def test_DiscoverRemoteSystems_success(observation):
    assert observation.success == True

@pytest.fixture(scope='module')
def host_ips(stop_subnet, cyborg):
    ip_map = cyborg.get_ip_map()
    hostnames = SUBNETS[stop_subnet]

    return [ip_map[h] for h in hostnames]


@pytest.fixture(scope='module')
def expected_interfaces(subnet_cidr, host_ips):
    get_interface = lambda ip: {'IP Address': ip,'Subnet': subnet_cidr}
    return [get_interface(ip) for ip in host_ips]


def test_DiscoverRemoteSystems_interfaces(observation, host_ips, expected_interfaces):
    interfaces = [observation.get_interfaces(ip)[0] for ip in host_ips]
    interfaces = itertools.chain(interfaces)

    assert list(interfaces) == expected_interfaces

def test_DiscoverRemoteSystems_processes(observation, host_ips):
    expected_processes = []

    processes = [observation.get_processes(ip)[0] for ip in host_ips \
            if len(observation.get_processes(ip)) > 0]
    processes = itertools.chain(processes)

    assert list(processes) == expected_processes

def test_DiscoverRemoteSystems_sessions(observation, host_ips):
    expected_sessions = []

    sessions = [observation.get_sessions(ip)[0] for ip in host_ips\
            if len(observation.get_processes(ip)) > 0]
    sessions = itertools.chain(sessions)

    assert list(sessions) == expected_sessions

def test_DiscoverRemoteSystems_os_info(observation, host_ips):
    expected_os_info = {}

    os_info = [observation.get_os_info(ip)[0] for ip in host_ips\
            if len(observation.get_processes(ip)) > 0]
    os_info = itertools.chain(os_info)

    assert dict(os_info) == expected_os_info

@pytest.fixture(params=EXPLOIT_PARAMETERS, scope='module')
def junk_action(request, cyborg):
    subnet = cyborg.get_cidr_map()['User']
    junk_action = DiscoverRemoteSystems(subnet=subnet, session=0, agent='Red')
    setattr(junk_action, request.param, 'Junk')

    return junk_action

@pytest.fixture(scope='module')
def junk_observation(cyborg, junk_action):
    results = cyborg.step(action=junk_action, agent='Red')

    return results.observation

def test_DiscoverRemoteSystems_junk_input_observation(junk_observation, junk_action):
    assert junk_observation == {'success':TrinaryEnum.UNKNOWN}

@pytest.fixture(scope='module')
def last_action(cyborg, junk_observation):
    # Junk observation required to ensure cyborg actually executes junk action
    return cyborg.get_last_action('Red')

def test_DiscoverRemoteSystems_junk_input_action(last_action):
    assert last_action.name == 'InvalidAction'

def test_DiscoverRemoteSystems_junk_input_replaced_action(last_action, junk_action):
    assert getattr(last_action, 'action') == junk_action

def test_DiscoverRemoteSystems_unscanned(cyborg, action, stop_subnet):
    cyborg.reset()
    action = DiscoverRemoteSystems(subnet=stop_subnet, agent='Red', session=0)
    results = cyborg.step(action=action, agent='Red')

    assert results.observation == {'success': TrinaryEnum.UNKNOWN}

