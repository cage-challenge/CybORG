from copy import deepcopy
from ipaddress import IPv4Network

import pytest

from CybORG.Agents.Utils import SubnetBelief
from CybORG.Simulator.Actions import DiscoverRemoteSystems

SUBNET = IPv4Network('10.0.33.64/28')

TEST_CASES = {
        'Default': {},
        'Scanned': {'scanned': True, 'hosts': set(['User0', 'User1']), 'has_firewall': True}
        }

TEST_CASE_NAMES = TEST_CASES.keys()
TEST_CASE_VALUES = [deepcopy(x) for x in TEST_CASES.values()]

@pytest.fixture(params=TEST_CASE_VALUES, ids=TEST_CASE_NAMES, scope='function')
def optional_params(request):
    return deepcopy(request.param)

@pytest.fixture(scope='function')
def input_params(optional_params):
    params = {'subnet': SUBNET}
    params.update(optional_params)

    return params

@pytest.fixture(scope='function')
def subnet_belief(input_params):
    return SubnetBelief(**input_params)

def test_SubnetBelief_subnet(subnet_belief, input_params):
    assert subnet_belief.subnet == input_params['subnet']

@pytest.mark.skip
def test_SubnetBelief_hosts(subnet_belief, input_params):
    assert subnet_belief.hosts == input_params.get('hosts', set())

def test_SubnetBelief_scanned(subnet_belief, input_params):
    assert subnet_belief.scanned == input_params.get('scanned', False)

def test_SubnetBelief_has_firewall(subnet_belief, input_params):
    assert subnet_belief.has_firewall == input_params.get('has_firewall', False)

def test_SubnetBelief_next_action(subnet_belief):
    assert subnet_belief.next_action == DiscoverRemoteSystems(SUBNET, agent='Red', session=0)


@pytest.fixture(params=['subnet', 'hosts', 'scanned'])
def alternate_belief(subnet_belief, request):
    alternate_belief = deepcopy(subnet_belief)
    setattr(alternate_belief, request.param, 'Junk')
    
    return alternate_belief

def test_SubnetBelief_inequality(subnet_belief, alternate_belief):
    assert subnet_belief != alternate_belief

