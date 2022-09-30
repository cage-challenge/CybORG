import inspect

import pytest
import random
import numpy as np
from gym import spaces
from pettingzoo.test import parallel_api_test

from CybORG import CybORG
from CybORG.Agents import RandomAgent
from CybORG.Agents.Wrappers.CommsPettingZooParallelWrapper import AgentCommsPettingZooParallelWrapper, ActionsCommsPettingZooParallelWrapper, ObsCommsPettingZooParallelWrapper
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator

@pytest.fixture(scope="function", params=[PettingZooParallelWrapper, AgentCommsPettingZooParallelWrapper, ActionsCommsPettingZooParallelWrapper, ObsCommsPettingZooParallelWrapper])
def create_wrapped_cyborg(request):
    sg = DroneSwarmScenarioGenerator()
    cyborg = CybORG(scenario_generator=sg, seed=123)
    return request.param(env=cyborg, max_steps=100)


@pytest.mark.skip('Agents are able to return to life')
def test_petting_zoo_parallel_wrapper(create_wrapped_cyborg):
    parallel_api_test(create_wrapped_cyborg, num_cycles=1000)


def test_attributes(create_wrapped_cyborg):
    # Create cyborg and reset it
    create_wrapped_cyborg.reset()

    # assert isinstance(obs, object) 
    assert isinstance(create_wrapped_cyborg.observation_spaces, dict)
    assert isinstance(create_wrapped_cyborg.rewards, dict)
    assert isinstance(create_wrapped_cyborg.dones, dict)
    assert isinstance(create_wrapped_cyborg.infos, dict)

    # Check action spaces is a dictionary
    assert isinstance(create_wrapped_cyborg.action_spaces, dict)

    # Check observation space is a dictionary
    assert isinstance(create_wrapped_cyborg.observation_spaces, dict)


def test_agent_data_change(create_wrapped_cyborg):
    create_wrapped_cyborg.reset()
    for agent in create_wrapped_cyborg.agents:
        assert isinstance(create_wrapped_cyborg.observation_space(agent), spaces.MultiDiscrete)
        assert isinstance(create_wrapped_cyborg.action_space(agent), spaces.Discrete)
        assert isinstance(create_wrapped_cyborg.get_reward(agent), float)
        assert isinstance(create_wrapped_cyborg.get_done(agent), bool)
        assert isinstance(create_wrapped_cyborg.infos, dict)

    actions = {}
    for agent in create_wrapped_cyborg.agents:
        actions[agent] = create_wrapped_cyborg.action_spaces[agent].sample()
    assert isinstance(actions, dict)
    obs, rews, dones, infos = create_wrapped_cyborg.step(actions)

    for agent in create_wrapped_cyborg.agents:
        assert isinstance(obs[agent], np.ndarray)
        assert isinstance(rews[agent], float)
        assert isinstance(dones[agent], bool)
        assert isinstance(infos, dict)


def test_steps_random(create_wrapped_cyborg):
    '''
    Select n random actions and steps through the environment x times
    '''
    # Create cyborg and reset it
    create_wrapped_cyborg.reset()
    # Steps through the environment, takes actions, resets and repeats
    MAX_STEPS_PER_GAME = 20
    MAX_EPS = 5

    for i in range(MAX_EPS):
        for j in range(MAX_STEPS_PER_GAME):
            # Create a dictionary that contains the actions selected by every agent
            actions = {}
            for agent in create_wrapped_cyborg.agents:
                actions[agent] = create_wrapped_cyborg.action_spaces[agent].sample()
            assert isinstance(actions, dict)

            obs, rews, dones, infos = create_wrapped_cyborg.step(actions)
            if j == MAX_STEPS_PER_GAME - 1:
                break
        create_wrapped_cyborg.reset()


'''
def test_get_attr(cyborg):
    for attribute in ['observation_spaces','action_spaces','observation_space','action_space',
            'get_action_space', 'observation_change', 'get_rewards', 'get_reward', 'get_dones', 'get_done']:
        assert cyborg.get_attr(attribute) == cyborg.env.get_attr(attribute)
'''


def test_observation_change(create_wrapped_cyborg):
    # Create cyborg and reset it
    create_wrapped_cyborg.reset()
    initial_obs = create_wrapped_cyborg.observation_spaces
    for i in range(5):
        actions = {}
        for agent in create_wrapped_cyborg.agents:
            actions[agent] = create_wrapped_cyborg.action_spaces[agent].sample()
        obs, rews, dones, infos = create_wrapped_cyborg.step(actions)
        for agent in create_wrapped_cyborg.agents:
            assert isinstance(obs[agent], np.ndarray)
            assert isinstance(rews, dict)
            assert isinstance(dones, dict)
            assert isinstance(infos, dict)

    final_obs = create_wrapped_cyborg.observation_spaces
    assert (initial_obs == final_obs)


def test_action_space(create_wrapped_cyborg):
    # Create cyborg and reset it
    create_wrapped_cyborg.reset()

    act_ss = create_wrapped_cyborg.action_spaces
    min_action_space_size = 1
    for agent in create_wrapped_cyborg.agents:
        act_s = act_ss[agent]
        assert isinstance(act_s, spaces.Discrete)


'''
def test_get_last_actions(cyborg):
    cyborg.reset()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')
    cyborg.step()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')
'''


def test_extreme_positions_drones():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=10000,
                                     starting_positions=[np.array([0, 0]), np.array([100, 100])])
    cyborg_raw = CybORG(scenario_generator=sg)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw, max_steps=100)
    for agent in cyborg.agents:
        obs = cyborg.get_observation(agent)
        assert cyborg.observation_space(agent).contains(obs)


def test_invalid_positions_drones():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=10000,
                                     starting_positions=[np.array([-1, -1]), np.array([101, 101])])
    cyborg_raw = CybORG(scenario_generator=sg)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw, max_steps=100)
    for agent in cyborg.agents:
        obs = cyborg.get_observation(agent)
        assert cyborg.observation_space(agent).contains(obs)


def test_active_agent_in_observation():
    sg = DroneSwarmScenarioGenerator(num_drones=20, max_length_data_links=10, starting_num_red=0)
    cyborg_raw = CybORG(scenario_generator=sg, seed=123)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw, max_steps=100)
    agents = {agent: RandomAgent() for agent in cyborg.possible_agents}
    action_spaces = cyborg.action_spaces
    for i in range(100):
        obs = cyborg.reset()
        for agent in cyborg.agents:
            assert agent in obs
            assert agent in action_spaces
            assert agent in agents
        for j in range(100):
            actions = {agent_name: agents[agent_name].get_action(obs[agent_name], action_spaces[agent_name])
                       for agent_name in cyborg.agents}
            obs, _, dones, _ = cyborg.step(actions)
            for agent in cyborg.agents:
                assert agent in obs
            if any(dones.values()):
                break

def test_observation():
    sg = DroneSwarmScenarioGenerator(num_drones=20, max_length_data_links=10, starting_num_red=0)
    cyborg_raw = CybORG(scenario_generator=sg, seed=123)

    cyborg = PettingZooParallelWrapper(env=cyborg_raw, max_steps=100)
