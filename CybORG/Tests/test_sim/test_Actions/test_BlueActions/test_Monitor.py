import pytest 
import itertools 
from copy import deepcopy

from CybORG.Tests.test_sim.sim_fixtures import create_cyborg, blue_observation_history, SCENARIOS
from CybORG.Agents.Utils import ObservationWrapper
from CybORG.Agents import MonitorAgent
from CybORG.Simulator.Actions import Monitor
from CybORG.Shared.Enums import SessionType, OperatingSystemType, ProcessType, ProcessState, TrinaryEnum
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort

SCENARIO = 'Scenario2'
EXPLOIT_PARAMETERS = ['session', 'agent', 'hostname']
HOSTS = []

@pytest.fixture
def history():
    return blue_observation_history(SCENARIO, MonitorAgent)

@pytest.fixture
def pingsweep_observations(history):
    return [ObservationWrapper(x[1]) for x in history \
            if x[0].name == 'DiscoverRemoteSystems']

def test_pingsweep_success(pingsweep_observations):
    successes = [x.success for x in pingsweep_observations]
    is_true = lambda x: x == True

    assert all([is_true(x) for x in successes])

def test_pingsweep_num_hosts(pingsweep_observations):
    lengths = [len(x.hosts) for x in pingsweep_observations]
    is_zero = lambda x: x == 0

    assert all([is_zero(x) for x in lengths])

@pytest.fixture
def portscan_observations(history):
    return [ObservationWrapper(x[1]) for x in history \
            if x[0].name == 'DiscoverNetworkServices']

def test_portscan_success(portscan_observations):
    successes = [x.success for x in portscan_observations]
    is_true = lambda x: x == True

    assert all([is_true(x) for x in successes])

def test_portscan_num_hosts(portscan_observations):
    lengths = [len(x.hosts) for x in portscan_observations]
    is_one = lambda x: x == 1

    assert all([is_one(x) for x in lengths])

@pytest.fixture
def exploit_observations(history):
    return [ObservationWrapper(x[1]) for x in history \
            if x[0].name == 'ExploitRemoteSytems']

def test_exploit_success(exploit_observations):
    successes = [x.success for x in exploit_observations]
    is_true = lambda x: x == True

    assert all([is_true(x) for x in successes])

def test_exploit_num_hosts(exploit_observations):
    lengths = [len(x.hosts) for x in exploit_observations]
    is_one = lambda x: x == 1

    assert all([is_one(x) for x in lengths])

@pytest.fixture
def impact_observations(history):
    return [ObservationWrapper(x[1]) for x in history \
            if x[0].name == 'DiscoverRemoteSystems']

def test_impact_success(impact_observations):
    successes = [x.success for x in impact_observations]
    is_true = lambda x: x == True

    assert all([is_true(x) for x in successes])

def test_impact_num_hosts(impact_observations):
    lengths = [len(x.hosts) for x in impact_observations]
    is_zero = lambda x: x == 0

    assert all([is_zero(x) for x in lengths])

@pytest.fixture
def privesc_observations(history):
    return [ObservationWrapper(x[1]) for x in history \
            if x[0].name == 'PrivilegeEscalation']

def test_privesc_success(privesc_observations):
    successes = [x.success for x in privesc_observations]
    is_true = lambda x: x == True

    assert all([is_true(x) for x in successes])

def test_privesc_num_hosts(privesc_observations):
    lengths = [len(x.hosts) for x in privesc_observations]
    is_one = lambda x: x == 1

    assert all([is_one(x) for x in lengths])

@pytest.fixture(scope='module')
def cyborg(target_host):
    return create_cyborg(SCENARIO)

@pytest.fixture(params=HOSTS, scope='module')
def target_host(request):
    return request.param

@pytest.fixture(scope='module')
def action(target_host):
    return Monitor(hostname=target_host, agent='Blue', session=0)

@pytest.fixture(scope='module')
def observation(action, cyborg):
    results = cyborg.step(action, agent='Blue', session=0)

    return ObservationWrapper(results.observation)

def test_Monitor_blank_success(observation):
    assert observation.success == True

def test_Monitor_blank_hosts(observation):
    assert len(observation.hosts) == 0

@pytest.fixture(params=EXPLOIT_PARAMETERS, scope='module')
def junk_action(action, request):
    junk_action = deepcopy(action) 
    setattr(junk_action, request.param, 'Junk')

    return junk_action

@pytest.fixture(scope='module')
def junk_observation(cyborg, junk_action):
    results = cyborg.step(action=junk_action, agent='Red')

    return results.observation

def test_Monitor_junk_input_observation(junk_observation, junk_action):
    assert junk_observation == {'success':TrinaryEnum.UNKNOWN}

@pytest.fixture(scope='module')
def last_action(cyborg, junk_observation):
    # Junk observation required to ensure cyborg actually executes junk action
    return cyborg.get_last_action('Red')

def test_Monitor_junk_input_action(last_action):
    assert last_action.name == 'InvalidAction'

def test_Monitor_junk_input_replaced_action(last_action, junk_action):
    assert getattr(last_action, 'action') == junk_action
