import pytest
import inspect

from CybORG import CybORG
from CybORG.Agents import B_lineAgent
from CybORG.Shared.Enums import TrinaryEnum
from CybORG.Simulator.Actions import Monitor, DiscoverRemoteSystems
from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator


def test_get_observation(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    for i in range(10):
        results = cyborg.step(agent='Blue',action=Monitor(session=0,agent='Blue'))
        step_obs = results.observation

        blue_obs = cyborg.get_observation('Blue')
        assert blue_obs == step_obs

        red_obs = cyborg.get_observation('Red')
        assert 'success' in red_obs
        assert len(red_obs.keys()) >= 1

def test_get_agent_state(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    cyborg.step(agent='Blue',action=Monitor(session=0,agent='Blue'))

    for agent in ('Red','Blue','True'):
        obs = cyborg.get_agent_state(agent)
        assert type(obs) == dict

        for hostid in obs:
            if hostid == 'success':
                continue
            host = obs[hostid]
            assert type(host) == dict
            if '_router' in hostid:
                attributes = set(['Interface','System info'])
            else:
                attributes = set(['Interface','Processes','Sessions','System info','User Info'])
                attributes.remove('User Info') if agent == 'Red' else None
            assert set(host.keys()) == attributes

def test_get_action_space(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    for agent in ('Red','Blue'):
        action_space = cyborg.get_action_space(agent)
    assert type(action_space) == dict
    assert list(action_space.keys()) == ['action', 'subnet', 'ip_address', 'session', 'username', 
            'password', 'process', 'port', 'target_session', 'agent', 'hostname']

def test_get_last_action(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    cyborg.reset()
    red_action = cyborg.get_last_action('Red')
    blue_action = cyborg.get_last_action('Blue')
    assert red_action == None
    assert blue_action == None
    cyborg.step(agent='Blue',action=Monitor(session=0,agent='Blue'))

    red_action = cyborg.get_last_action('Red')
    assert type(red_action) == DiscoverRemoteSystems

    blue_action = cyborg.get_last_action('Blue')
    assert type(blue_action) == Monitor

def test_get_ip_map(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    ip_map = cyborg.get_ip_map()
    assert type(ip_map) == dict
    assert sorted(list(ip_map.keys())) == sorted(['Enterprise0', 'Enterprise1', 'Enterprise2', 'Enterprise_router', 'Defender', 'Op_Server0', 'Op_Host0', 'Op_Host1', 'Op_Host2', 'Operational_router', 'User0', 'User1', 'User2', 'User3', 'User4', 'User_router'])

def test_get_rewards(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    cyborg.step(agent='Blue',action=Monitor(session=0,agent='Blue'))
    rewards = cyborg.get_rewards()
    assert type(rewards) == dict
    assert set(rewards.keys()) == set(['Red','Blue','Green'])

def test_get_attr(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    for attribute in ['get_observation','get_action_space','get_last_action','get_ip_map',
            'get_rewards', 'get_agent_state']:
        method_output = cyborg.get_attr(attribute)
        class_output = cyborg.__getattribute__(attribute)
        assert method_output == class_output

@pytest.mark.skip
def test_get_reward_breakdown(cyborg_scenario1b_bline):
    cyborg = cyborg_scenario1b_bline
    for i in range(30):
        cyborg.step()

    red_rewards = cyborg.get_reward_breakdown('Red')
    assert False

    blue_rewards = cyborg.get_reward_breakdown('Blue')
    assert False

