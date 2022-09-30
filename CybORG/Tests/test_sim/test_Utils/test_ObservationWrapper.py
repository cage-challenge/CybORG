from copy import deepcopy

import pytest

from utils_test_observations import (RED_INITIAL, RED_PINGSWEEP, RED_PORTSCAN, RED_EXPLOIT, RED_PRIVESC, OBS_SUCCESS,
        OBS_FAIL)
from CybORG.Agents.Utils.ObservationWrapper import ObservationWrapper
from CybORG.Shared.Enums import TrinaryEnum, OperatingSystemType

TEST_CASES = {
        'RED_INITIAL': RED_INITIAL,
        'RED_PINGSWEEP': RED_PINGSWEEP,
        'RED_PORTSCAN': RED_PORTSCAN,
        'RED_EXPLOIT': RED_EXPLOIT,
        'RED_PRIVESC': RED_PRIVESC,
        'OBS_SUCCESS': OBS_SUCCESS,
        'OBS_FAIL': OBS_FAIL
        }

@pytest.fixture(params=TEST_CASES.values(), ids=TEST_CASES.keys(), scope='function')
def obs(request):
    return request.param

@pytest.fixture(scope='function')
def wrapper(obs):
    return ObservationWrapper(obs)

@pytest.fixture
def string_obs(obs):
    keys = [str(k) for k in obs]
    values = obs.values()

    return dict(zip(keys, values))

def test_ObservationWrapper_success(wrapper, obs):
    assert wrapper.success == obs['success']

def test_ObservationWrapper_hosts(wrapper, string_obs):
    assert wrapper.hosts == {str(k):v for k,v in string_obs.items() if k!= 'success'}

def test_ObservationWrapper_get_interfaces(wrapper, string_obs):
    expected_interfaces = [string_obs[h].get('Interface', []) for h in wrapper.hosts]
    assert [wrapper.get_interfaces(h) for h in wrapper.hosts] == expected_interfaces

def test_ObservationWrapper_get_processes(wrapper, string_obs):
    expected_processes = [string_obs[h].get('Processes', []) for h in wrapper.hosts]

    assert [wrapper.get_processes(h) for h in wrapper.hosts] == expected_processes

def test_ObservationWrapper_get_sessions(wrapper, string_obs):
    expected_sessions = [string_obs[h].get('Sessions', []) for h in wrapper.hosts]

    assert [wrapper.get_sessions(h) for h in wrapper.hosts] == expected_sessions

def test_ObservationWrapper_os_info(wrapper, string_obs):
    expected_os_info = [string_obs[h].get('System info',{}) for h in wrapper.hosts]

    assert [wrapper.get_os_info(h) for h in wrapper.hosts] == expected_os_info

def test_ObservationWrapper_get_ip(wrapper):
    primary_interfaces = [wrapper.get_interfaces(h)[0] for h in wrapper.hosts]
    expected_ips = [i.get('IP Address', None) for i in primary_interfaces]

    assert [wrapper.get_ip(h) for h in wrapper.hosts] == expected_ips

def test_ObservationWrapper_get_subnet(wrapper):
    primary_interfaces = [wrapper.get_interfaces(h)[0] for h in wrapper.hosts]
    expected_subnets = [i.get('Subnet', None) for i in primary_interfaces]

    assert [wrapper.get_subnet(h) for h in wrapper.hosts] == expected_subnets

def test_ObservationWrapper_has_red_access(wrapper):
    sessions = [wrapper.get_sessions(h) for h in wrapper.hosts]
    is_red_session = lambda s: s.get('Agent', None) == 'Red'
    has_red_session = lambda t: any([is_red_session(s) for s in t])
    expected_access = [has_red_session(t) for t in sessions]

    assert [wrapper.has_red_access(h) for h in wrapper.hosts] == expected_access

def test_ObservationWrapper_has_root_access(wrapper):
    sessions = [wrapper.get_sessions(h) for h in wrapper.hosts]
    is_red_session = lambda s: s.get('Agent', None) == 'Red'
    is_red_root_session = lambda s: s.get('Username', None) in ('SYSTEM', 'root') and \
            is_red_session(s)
    has_red_root_session = lambda t: any([is_red_root_session(s) for s in t])
    expected_access = [has_red_root_session(t) for t in sessions]

    assert [wrapper.has_red_access(h, only_root=True) for h in wrapper.hosts] == expected_access

def test_ObservationWrapper_get_hostname(wrapper):
    os_info = [wrapper.get_os_info(h) for h in wrapper.hosts]
    expected_hostnames = [x.get('Hostname', None) for x in os_info]

    assert [wrapper.get_hostname(h) for h in wrapper.hosts] == expected_hostnames

def test_ObservationWrapper_get_os(wrapper):
    os_info = [wrapper.get_os_info(h) for h in wrapper.hosts]
    expected_os = [x.get('OSType', None) for x in os_info]

    assert [wrapper.get_os(h) for h in wrapper.hosts] == expected_os

@pytest.mark.skip
def test_ObservationWrapper_is_formatted_correctly(wrapper):
    raise NotImplementedError

