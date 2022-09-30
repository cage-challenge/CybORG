import pytest 
import itertools 
from copy import deepcopy

from CybORG.Tests.test_sim.sim_fixtures import compromised_cyborg, SCENARIOS
from CybORG.Agents.Utils import ObservationWrapper
from CybORG.Simulator.Actions import PrivilegeEscalate, PrivilegeEscalate
from CybORG.Shared.Enums import SessionType, OperatingSystemType, ProcessType, ProcessState, TrinaryEnum
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort, PID

SCENARIO = 'Scenario2'
HOSTS = SCENARIOS[SCENARIO]['Hosts']
SUBNETS = SCENARIOS[SCENARIO]['Subnets']
OS_MAP = SCENARIOS[SCENARIO]['OS_Map']
invulnerable_hosts = ['Defender', 'Op_Host0', 'Op_Host1', 'Op_Host2']
VULNERABLE_HOSTS = [h for h in HOSTS if h not in invulnerable_hosts]

EXPLOIT_PARAMETERS = ['session', 'agent', 'hostname']

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
    return compromised_cyborg(SCENARIO, stop_host='Op_Server0', stop_value=2)

@pytest.fixture(scope='module')
def action(target_host, cyborg):
    return PrivilegeEscalate(hostname=target_host, agent='Red', session=0)

@pytest.fixture(scope='module')
def observation(cyborg, action):
    results = cyborg.step(action=action, agent='Red')

    return ObservationWrapper(results.observation)

def test_PrivilegeEscalate_success(observation, target_host):
    assert observation.success == (True if target_host in VULNERABLE_HOSTS else TrinaryEnum.UNKNOWN)

@pytest.fixture()
def length(target_host):
    if target_host in invulnerable_hosts:
        return 0
    elif target_host in ['User0', 'Enterprise0', 'Enterprise1', 'Op_Server0']:
        return 1
    else:
        return 2

def test_PrivilegeEscalate_num_hosts(observation, length):
    assert len(observation.hosts) == length

@pytest.fixture()
def target_subnet(target_host, cyborg):
    for subnet in SUBNETS:
        if target_host in SUBNETS[subnet]:
            break

    return cyborg.get_cidr_map()[subnet]

def test_PrivilegeEscalate_target_interfaces(observation, target_host, target_ip, \
        target_subnet):
    interface = [{
        'IP Address': target_ip,
        'Interface Name': 'eth0',
        'Subnet': target_subnet,
        }]
    expected_interface = interface if target_host in VULNERABLE_HOSTS else []

    assert observation.get_interfaces(target_host) == expected_interface

@pytest.fixture
def username(target_host):
    os = OS_MAP[target_host]
    return 'SYSTEM' if os == OperatingSystemType.WINDOWS else 'root'

def test_PrivilegeEscalate_target_processes(observation, target_host, username):
    processes = [{'PID': PID(), 'Username': username},{'PID': PID(), 'Service Name': 'OTService'}] if target_host == 'Op_Server0' \
            else [{'PID': PID(), 'Username': username}]
    expected_processes = processes if target_host in VULNERABLE_HOSTS else []

    assert observation.get_processes(target_host) == expected_processes

class PrivEscSessionType():
    def __eq__(self, other):
        if other in [
                SessionType.RED_ABSTRACT_SESSION, 
                SessionType.SSH, 
                SessionType.RED_REVERSE_SHELL
                ]:
            return True
        else:
            return False

def test_PrivilegeEscalate_target_sessions(observation, target_host, username):
    agent_session = HOSTS.index(target_host) - (0 if HOSTS.index(target_host) < 8 else 1)
    sessions = [{
        'Username': username,
        'ID': agent_session,
        'Timeout': 0,
        'PID': PID(),
        'Type': PrivEscSessionType(),
        'Agent': 'Red',
        }]
    expected_sessions = sessions if target_host in VULNERABLE_HOSTS else []

    assert observation.get_sessions(target_host) == expected_sessions

def test_PrivilegeEscalate_target_os_info(observation, target_host):
    os_info = {}

    expected_os_info = os_info if target_host in VULNERABLE_HOSTS else {}

    assert observation.get_os_info(target_host) == expected_os_info

@pytest.fixture(params=EXPLOIT_PARAMETERS, scope='module')
def junk_action(action, request):
    junk_action = deepcopy(action) 
    setattr(junk_action, request.param, 'Junk')

    return junk_action

@pytest.fixture(scope='module')
def junk_observation(cyborg, junk_action):
    results = cyborg.step(action=junk_action, agent='Red')

    return results.observation

def test_PrivilegeEscalate_junk_input_observation(junk_observation, junk_action):
    assert junk_observation == {'success':TrinaryEnum.UNKNOWN}

@pytest.fixture(scope='module')
def last_action(cyborg, junk_observation):
    # Junk observation required to ensure cyborg actually executes junk action
    return cyborg.get_last_action('Red')

def test_PrivilegeEscalate_junk_input_action(last_action):
    assert last_action.name == 'InvalidAction'

def test_PrivilegeEscalate_junk_input_replaced_action(last_action, junk_action):
    assert getattr(last_action, 'action') == junk_action

def test_PrivilegeEscalate_unscanned(cyborg, target_host, action):
    if target_host == 'User0':
        return
    cyborg.reset()
    target_ip = cyborg.get_ip_map()[target_host]
    action = PrivilegeEscalate(hostname=target_host, agent='Red', session=0)
    results = cyborg.step(action=action, agent='Red')

    assert results.observation == {'success': TrinaryEnum.UNKNOWN}

