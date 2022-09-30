from copy import deepcopy
from ipaddress import IPv4Address, IPv4Network

import pytest

from CybORG.Agents.Utils import HostBelief, HostStatus
from CybORG.Simulator.Actions import DiscoverNetworkServices, ExploitRemoteService, PrivilegeEscalate, Impact

TARGET_HOST = 'User1'
SUBNET = IPv4Network('10.0.33.64/28')

TEST_CASES = {
        'Default': {},
        'Scanned': {'status': HostStatus.SCANNED},
        'Defender': {'status': HostStatus.SCANNED, 'is_defender': True},
        'User Access': {'status': HostStatus.USER_ACCESS, 'name': TARGET_HOST},
        'Op_Server': {'status': HostStatus.USER_ACCESS, 'name': TARGET_HOST, 'is_opserver': True},
        'Privileged Access': {'status': HostStatus.PRIVILEGED_ACCESS, 'name': TARGET_HOST,  'subnet': SUBNET}
        }

TEST_CASE_NAMES = TEST_CASES.keys()
TEST_CASE_VALUES = [deepcopy(x) for x in TEST_CASES.values()]

@pytest.fixture(params=TEST_CASE_VALUES, ids=TEST_CASE_NAMES, scope='function')
def optional_params(request):
    return deepcopy(request.param)

@pytest.fixture(scope='function')
def input_params(optional_params):
    ip = IPv4Address('10.0.33.73')
    params = {'ip': ip}
    params.update(optional_params)

    return params


@pytest.fixture(scope='function')
def host_belief(input_params):
    return HostBelief(**input_params)

def test_SubnetBelief_ip(host_belief, input_params):
    assert host_belief.ip == input_params['ip']

def test_SubnetBelief_subnet(host_belief, input_params):
    assert host_belief.subnet == input_params.get('subnet', None)

def test_SubnetBelief_name(host_belief, input_params):
    assert host_belief.name == input_params.get('name', None)

def test_SubnetBelief_status(host_belief, input_params):
    assert host_belief.status == input_params.get('status', HostStatus.DISCOVERED)

def test_SubnetBelief_is_defender(host_belief, input_params):
    assert host_belief.is_defender == input_params.get('is_defender', False)

def test_SubnetBelief_is_opserver(host_belief, input_params):
    assert host_belief.is_opserver == input_params.get('is_opserver', False)

@pytest.fixture(params=['ip', 'subnet', 'name', 'status', 'is_defender', 'is_opserver'])
def alternate_belief(host_belief, request):
    alternate_belief = deepcopy(host_belief)
    setattr(alternate_belief, request.param, 'Junk')
    
    return alternate_belief

def test_HostBelief_inequality(host_belief, alternate_belief):
    assert host_belief != alternate_belief

@pytest.fixture
def red_killchain():
    killchain = [
            DiscoverNetworkServices,
            ExploitRemoteService,
            PrivilegeEscalate,
            Impact
            ]

    return killchain

def test_HostBelief_next_action(host_belief, input_params, red_killchain):
    current_status = host_belief.status.value
    expected_action_class = red_killchain[current_status]

    hostname = host_belief.name
    expected_target = hostname
    if hostname is not None:
        expected_next_action = expected_action_class(hostname=expected_target, agent='Red', session=0)
    else:
        expected_next_action = expected_action_class(ip_address=host_belief.ip, agent='Red', session=0)

    assert host_belief.next_action == expected_next_action

def test_HostBelief_advance_killchain(host_belief):
    host_belief = deepcopy(host_belief)
    initial_value = host_belief.status.value
    host_belief.advance_killchain()

    assert host_belief.status.value == min(initial_value + 1, 3)

def test_HostBelief_restore(host_belief):
    host_belief = deepcopy(host_belief)
    expected_values = deepcopy(host_belief)
    expected_values.status = HostStatus.SCANNED

    host_belief.restore()

    assert host_belief == expected_values

