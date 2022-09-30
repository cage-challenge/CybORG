from copy import deepcopy
from ipaddress import IPv4Network, IPv4Address

import pytest

from utils_test_observations import (RED_INITIAL, RED_PINGSWEEP, RED_PORTSCAN, RED_EXPLOIT, RED_PRIVESC,  OBS_SUCCESS, 
        OBS_FAIL, TARGET_HOST, TARGET_IP, SUBNET, SOURCE_HOST, SOURCE_IP, SUBNET_IPS, ENTERPRISE_IP)
from CybORG.Simulator.Actions import (DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, 
        PrivilegeEscalate, Impact)
from CybORG.Agents.Utils import RedAgentBelief, SubnetBelief, HostBelief, HostStatus

PARAMS = {'session':0, 'agent':'Red'}

TEST_CASES = {
        'Initial Observation': {'observation': RED_INITIAL, 'action': None},
        'Pingsweep Observation': {'observation': RED_PINGSWEEP, 'action': DiscoverRemoteSystems(SUBNET, **PARAMS)},
        'Portscan Observation': {'observation': RED_PORTSCAN, 'action': DiscoverNetworkServices(ip_address=TARGET_IP, **PARAMS)},
        'Exploit Observation': {'observation': RED_EXPLOIT, 'action': ExploitRemoteService(TARGET_IP, **PARAMS)},
        'PrivEsc Observation': {'observation': RED_PRIVESC, 'action': PrivilegeEscalate(TARGET_HOST, **PARAMS)},
        'Impact Observation': {'observation': OBS_SUCCESS, 'action': Impact(TARGET_HOST, **PARAMS)}
        }

TEST_CASE_NAMES = TEST_CASES.keys()
TEST_CASE_VALUES = [deepcopy(x) for x in TEST_CASES.values()]

@pytest.skip(allow_module_level=True)
# Any test that calls belief breaks the other utils tests

@pytest.fixture(params=TEST_CASE_VALUES, ids=TEST_CASE_NAMES, scope='function')
def update_parameters(request, scope='function'):
    return request.param

@pytest.fixture()
def initial_belief():
    return RedAgentBelief()

def test_RedAgentBelief_initial_last_action(initial_belief):
    assert initial_belief.last_action == None

def test_RedAgentBelief_initial_hosts(initial_belief):
    assert initial_belief.hosts == {}

def test_RedAgentBelief_initial_subnets(initial_belief):
    assert initial_belief.subnets == {}

@pytest.fixture(scope='function')
def persistent_belief():
    return RedAgentBelief()

@pytest.fixture(scope='function')
def belief(persistent_belief, update_parameters):
    persistent_belief.update(**update_parameters)

    return persistent_belief

@pytest.fixture(params=['last_action', 'hosts', 'subnets'])
def alternate_belief(belief, request):
    alternate_belief = deepcopy(belief)
    setattr(alternate_belief, request.param, 'Junk')
    
    return alternate_belief

def test_RedAgentBelief_inequality(belief, alternate_belief):
    assert belief != alternate_belief

def test_RedAgentBelief_clear(belief, initial_belief):
    belief = deepcopy(belief)
    belief.clear()

    assert belief == initial_belief

@pytest.fixture(scope='function')
def last_action(update_parameters):
    return update_parameters['action']

def test_expected_last_action(belief, last_action):
    assert belief.last_action == last_action

@pytest.fixture
def expected_subnets(last_action):
    subnet_params = {
            'subnet': SUBNET,
            'hosts': set([SOURCE_IP]) if last_action is None else set(SUBNET_IPS),
            'scanned': last_action is not None
            }

    return {str(SUBNET): SubnetBelief(**subnet_params)}

def test_expected_subnets(belief, expected_subnets):
    assert belief.subnets == expected_subnets

@pytest.fixture
def expected_source_belief():
    source_host_params = {
            'ip': SOURCE_IP,
            'subnet': SUBNET,
            'name': SOURCE_HOST,
            'status': HostStatus.PRIVILEGED_ACCESS
            }

    return HostBelief(**source_host_params)

@pytest.fixture
def expected_target_belief(last_action):
    if last_action is None:
        return None

    belief = HostBelief(TARGET_IP, subnet=SUBNET)

    for name in ['DiscoverRemoteSystems', 'DiscoverNetworkServices', 'ExploitRemoteService']:
        if name == 'ExploitRemoteService':
            belief.name = TARGET_HOST

        if last_action.name == name:
            return belief
    
        belief.advance_killchain()

    if last_action.name == 'Impact':
        belief.is_opserver = True

    return belief

@pytest.fixture
def expected_hosts(last_action, expected_source_belief, expected_target_belief):
    if last_action is None:
        return {str(SOURCE_IP): expected_source_belief}

    hosts = {}
    for ip in SUBNET_IPS:
        if ip == SOURCE_IP:
            belief =  expected_source_belief
        elif ip == TARGET_IP:
            belief = expected_target_belief
        else:
            belief = HostBelief(ip, subnet=SUBNET)

        hosts[str(ip)] = belief

    if last_action.name in ('PrivilegeEscalate', 'Impact'):
        hosts[str(ENTERPRISE_IP)] = HostBelief(ENTERPRISE_IP)

    return hosts

def test_RedAgentBelief_hosts(belief, expected_hosts):
    assert belief.hosts == expected_hosts

def test_RedAgentBelief_get_unscanned_subnets(belief, last_action):
    expected_subnets = [SUBNET] if last_action is None else []

    assert belief.unscanned_subnets == expected_subnets

def test_RedAgentBelief_double_update(belief, update_parameters):
    belief = deepcopy(belief)
    expected_belief = deepcopy(belief)

    belief.update(**update_parameters)

    assert belief == expected_belief

@pytest.fixture(scope='function')
def full_belief(request):
    belief = RedAgentBelief()
    for params in TEST_CASE_VALUES:
        belief.update(**params)

    return belief

def test_RedAgentBelief_repeated_update(full_belief, update_parameters):
    if update_parameters['action'] is None:
        return

    belief = deepcopy(full_belief)
    expected_belief = deepcopy(full_belief)
    expected_belief.last_action = update_parameters['action']
    
    belief.update(**update_parameters)

    assert belief == expected_belief

@pytest.fixture()
def failure_update_params(belief, scope='function'):
    target = belief.subnets[str(SUBNET)] if belief.last_action is None else belief.hosts[str(TARGET_IP)]
    next_action = target.next_action

    input_params = {
            'observation': OBS_FAIL,
            'action': next_action,
            }

    return input_params

@pytest.fixture()
def failed_belief(belief, failure_update_params):
    action = failure_update_params['action']
    if action is None or action.name is 'DiscoverRemoteSystems':
        return belief

    belief = deepcopy(belief)
    belief.update(**failure_update_params)


    return belief

@pytest.fixture()
def expected_failed_belief(belief, failure_update_params):
    belief = deepcopy(belief)
    action = failure_update_params['action']
    belief.last_action = action
    
    if action.name == 'ExploitRemoteService':
        belief.hosts[str(TARGET_IP)].is_defender = True
    elif action.name == 'PrivilegeEscalate':
        target_host = belief.hosts[str(TARGET_IP)]
        target_host.status = HostStatus.SCANNED 
    elif action.name == 'Impact':
        target_host = belief.hosts[str(TARGET_IP)]
        target_host.status = HostStatus.SCANNED if target_host.is_opserver else HostStatus.PRIVILEGED_ACCESS

    return belief

def test_RedAgentBelief_failed_obs(failed_belief, expected_failed_belief):
    action = failed_belief.last_action
    if action is None or action.name is 'DiscoverRemoteSystems':
        return

    assert failed_belief == expected_failed_belief

ENTERPRISE_SUBNET = IPv4Network('10.0.22.64/28')
OPERATIONAL_SUBNET = IPv4Network('10.0.33.64/28')

@pytest.fixture()
def opserver_belief(belief):
    if belief.last_action is None or belief.last_action.name == 'DiscoverRemoteSystems':
        return None

    belief = deepcopy(belief)
    subnets = belief.subnets
    hosts = belief.hosts
    subnets[str(SUBNET)].hosts.remove(TARGET_IP)

    ent_ip_scanned = '22.22.22.21'
    hosts[ent_ip_scanned] = HostBelief(ent_ip_scanned, status=HostStatus.DISCOVERED)
    ent_ip_root = '22.22.22.22'
    hosts[ent_ip_root] = HostBelief(ent_ip_root, status=HostStatus.PRIVILEGED_ACCESS)
    subnets[ENTERPRISE_SUBNET] = SubnetBelief(ENTERPRISE_SUBNET, hosts=set([ent_ip_scanned, ent_ip_root]))

    hosts[str(TARGET_IP)].subnet = OPERATIONAL_SUBNET
    subnets[OPERATIONAL_SUBNET] = SubnetBelief(OPERATIONAL_SUBNET, hosts=set([TARGET_IP]))

    return belief

@pytest.fixture()
def failed_opserver_belief(opserver_belief, failure_update_params):
    if opserver_belief is None:
        return None

    belief = deepcopy(opserver_belief)
    belief.update(**failure_update_params)

    return belief

@pytest.fixture()
def expected_failed_opserver_belief(opserver_belief, failure_update_params):
    if opserver_belief is None:
        return

    belief = deepcopy(opserver_belief)

    action = failure_update_params['action']
    op_host = belief.hosts[str(TARGET_IP)]
    enterprise_hosts = belief.subnets[ENTERPRISE_SUBNET].hosts

    if action == 'DiscoverRemoteSystems':
        return belief
    
    op_host.status = HostStatus.DISCOVERED if action == 'DiscoverNetworkServices' else HostStatus.SCANNED

    if action in ('PrivilegeEscalate', 'Impact'):
        return belief

    for ip in enterprise_hosts:
        ent_host = belief.hosts[ip]
        if ent_host.status.value > 1:
            ent_host.status = HostStatus.SCANNED

    return belief

def test_RedAgentBelief_failed_opserver_belief(failed_opserver_belief, expected_failed_opserver_belief):
    assert failed_opserver_belief == failed_opserver_belief


