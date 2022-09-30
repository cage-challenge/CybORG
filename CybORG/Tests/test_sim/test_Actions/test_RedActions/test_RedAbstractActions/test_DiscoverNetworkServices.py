import pytest 
import itertools 
from copy import deepcopy

from CybORG.Tests.test_sim.sim_fixtures import compromised_cyborg, SCENARIOS
from CybORG.Agents.Utils import ObservationWrapper
from CybORG.Simulator.Actions import DiscoverNetworkServices
from CybORG.Shared.Enums import SessionType, OperatingSystemType, ProcessType, ProcessState, TrinaryEnum
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort

SCENARIO = 'Scenario2'
HOSTS = SCENARIOS[SCENARIO]['Hosts']
VULNERABLE_HOSTS = HOSTS
OS_MAP = SCENARIOS[SCENARIO]['OS_Map']
PORT_MAP = {
        'User0': [22, 21],
        'User1': [22, 21],
        'User2': [445, 139, 135, 3389],
        'User3': [80, 3389, 443, 25],
        'User4': [22, 80, 3390, 443, 25],
        'Enterprise0': [22],
        'Enterprise1': [22, 135, 3389, 445, 139, 80, 443],
        'Enterprise2': [22, 135, 3389, 445, 139, 80, 443],
        'Defender': [22, 53, 53, 68],
        'Op_Server0': [22],
        'Op_Host0': [22],
        'Op_Host1': [22],
        'Op_Host2': [22],
        }

EXPLOIT_PARAMETERS = ['session', 'agent', 'ip_address']

@pytest.fixture(scope='module')
def source_host():
    return 'User0'

@pytest.fixture(scope='module')
def source_ip(cyborg):
    return cyborg.get_ip_map()['User0']

@pytest.fixture(params=HOSTS, scope='module')
def target_host(request):
    return request.param

@pytest.fixture(scope='module')
def target_ip(cyborg, target_host):
    return cyborg.get_ip_map()[target_host]

@pytest.fixture(scope='module')
def cyborg(target_host):
    return compromised_cyborg(SCENARIO, stop_host=target_host, stop_value=1)

@pytest.fixture(scope='module')
def action(target_ip, cyborg):
    return DiscoverNetworkServices(ip_address=target_ip, agent='Red', session=0)

@pytest.fixture(scope='module')
def observation(cyborg, action):
    results = cyborg.step(action=action, agent='Red')

    return ObservationWrapper(results.observation)

def test_DiscoverNetworkServices_success(observation, target_host):
    assert observation.success == (True if target_host in VULNERABLE_HOSTS else False)

def test_DiscoverNetworkServices_num_hosts(observation, target_host):
    assert len(observation.hosts) == (1 if target_host in VULNERABLE_HOSTS else 0)

def test_DiscoverNetworkServices_target_interfaces(observation, target_ip, target_host):
    interface = [{'IP Address': target_ip}]
    expected_interface = interface if target_host in VULNERABLE_HOSTS else []

    assert observation.get_interfaces(target_ip) == expected_interface

def test_DiscoverNetworkServices_target_processes(observation, target_ip, target_host, source_ip):
    os = OS_MAP[target_host]
    local_port = Win2008EphemeralPort() if os == OperatingSystemType.WINDOWS \
            else LinuxEphemeralPort()

    processes = []
    for port in PORT_MAP[target_host]:
        connection = [{
                'local_port': port,
                'local_address': target_ip,
                }]
        process = {'Connections': connection,}
        processes.append(process)

    expected_processes = processes if target_host in VULNERABLE_HOSTS else []

    assert observation.get_processes(target_ip) == expected_processes

def test_DiscoverNetworkServices_target_sessions(observation, target_ip, target_host, cyborg):
    agent_session = HOSTS.index(target_host)
    sessions = []
    expected_sessions = sessions if target_host in VULNERABLE_HOSTS else []

    assert observation.get_sessions(target_ip) == expected_sessions

def test_DiscoverNetworkServices_target_os_info(observation, target_ip, target_host):
    os = OS_MAP[target_host]
    os_info = {}

    expected_os_info = os_info if target_host in VULNERABLE_HOSTS else {}

    assert observation.get_os_info(target_ip) == expected_os_info

@pytest.fixture(params=EXPLOIT_PARAMETERS, scope='module')
def junk_action(action, request):
    junk_action = deepcopy(action) 
    setattr(junk_action, request.param, 'Junk')

    return junk_action

@pytest.fixture(scope='module')
def junk_observation(cyborg, junk_action):
    results = cyborg.step(action=junk_action, agent='Red')

    return results.observation

def test_DiscoverNetworkServices_junk_input_observation(junk_observation, junk_action):
    assert junk_observation == {'success':TrinaryEnum.UNKNOWN}

@pytest.fixture(scope='module')
def last_action(cyborg, junk_observation):
    # Junk observation required to ensure cyborg actually executes junk action
    return cyborg.get_last_action('Red')

def test_DiscoverNetworkServices_junk_input_action(last_action):
    assert last_action.name == 'InvalidAction'

def test_DiscoverNetworkServices_junk_input_replaced_action(last_action, junk_action):
    assert getattr(last_action, 'action') == junk_action

def test_DiscoverNetworkServices_unknown(cyborg, target_host, action):
    if target_host == 'User0':
        return

    cyborg.reset()
    target_ip = cyborg.get_ip_map()[target_host]
    action = DiscoverNetworkServices(ip_address=target_ip, agent='Red', session=0)
    results = cyborg.step(action=action, agent='Red')

    assert results.observation == {'success': TrinaryEnum.UNKNOWN}

