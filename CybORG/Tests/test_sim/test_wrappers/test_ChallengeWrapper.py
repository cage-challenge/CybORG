import inspect
from ipaddress import IPv4Address, IPv4Network

import pytest
import numpy as np
from prettytable import PrettyTable

from CybORG import CybORG
from CybORG.Agents import B_lineAgent, BlueMonitorAgent
from CybORG.Agents.Wrappers import ChallengeWrapper

@pytest.fixture()
def cyborg(request,agents = {'Blue':BlueMonitorAgent,'Red':B_lineAgent},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'

    cyborg = ChallengeWrapper(env=CybORG(path, 'sim',agents=agents),
            agent_name='Blue')
    cyborg.set_seed(seed)
    return cyborg

def test_ChallengeWrapper_reset(cyborg):
    obs = cyborg.reset()
    expected_observation = np.array([0 for x in range(52)])
    assert all(obs == expected_observation)

def test_ChallengeWrapper_step(cyborg):
    cyborg.reset()
    obs,reward,done,info = cyborg.step(action=0)
    expected_observation = np.array([0 for x in range(52)])
    assert all(obs == expected_observation)
    assert reward == 0
    assert done == False
    assert type(info) == dict

def test_get_attr(cyborg):
    for attribute in ['get_observation','get_action_space','get_last_action','get_ip_map',
            'get_rewards', 'get_agent_state']:
        assert cyborg.get_attr(attribute) == cyborg.env.get_attr(attribute)

def test_get_observation(cyborg):
    agent = cyborg.agent_name
    cyborg.reset()
    assert cyborg.get_observation(agent) == cyborg.get_attr('get_observation')(agent)
    cyborg.step()
    assert cyborg.get_observation(agent) == cyborg.get_attr('get_observation')(agent)

def test_get_agent_state(cyborg):
    cyborg.reset()
    cyborg.step()
    assert cyborg.get_agent_state('True') == cyborg.get_attr('get_agent_state')('True')
    assert cyborg.get_agent_state('Red') == cyborg.get_attr('get_agent_state')('Red')
    assert cyborg.get_agent_state('Blue') == cyborg.get_attr('get_agent_state')('Blue')

def test_get_action_space(cyborg):
    red_space = cyborg.get_action_space(cyborg.agent)
    red_space == 41

def test_get_last_action(cyborg):
    cyborg.reset()
    assert cyborg.get_last_action('Red') is None
    assert cyborg.get_last_action('Blue') is None
    cyborg.step()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')

def test_get_ip_map(cyborg):
    assert cyborg.get_ip_map() == cyborg.get_attr('get_ip_map')()

def test_get_rewards(cyborg):
    assert cyborg.get_rewards() == cyborg.get_attr('get_rewards')()
