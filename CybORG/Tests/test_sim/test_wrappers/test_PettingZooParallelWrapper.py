import inspect

import pytest
import random
import numpy as np
from gym import spaces
from pettingzoo.test import parallel_api_test

from CybORG import CybORG
from CybORG.Agents import RandomAgent, DroneRedAgent, SleepAgent
from CybORG.Agents.Wrappers.CommsPettingZooParallelWrapper import AgentCommsPettingZooParallelWrapper, ActionsCommsPettingZooParallelWrapper, ObsCommsPettingZooParallelWrapper
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Simulator.Actions import ExploitDroneVulnerability
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator
from CybORG.Tests.utils import AlwaysTrueGenerator


@pytest.fixture(scope="function", params=[PettingZooParallelWrapper, AgentCommsPettingZooParallelWrapper, ActionsCommsPettingZooParallelWrapper, ObsCommsPettingZooParallelWrapper])
def create_wrapped_cyborg(request):
    sg = DroneSwarmScenarioGenerator()
    cyborg = CybORG(scenario_generator=sg, seed=123)
    return request.param(env=cyborg)


@pytest.mark.skip('Agents are able to return to life')
def test_petting_zoo_parallel_wrapper(create_wrapped_cyborg):
    parallel_api_test(create_wrapped_cyborg, num_cycles=1000)



#Test if actions inputted are valid
def test_valid_actions():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=10000, starting_num_red=0)
    cyborg_raw = CybORG(scenario_generator=sg, seed=123)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()

    for i in range(50):
        actions = {}
        for agent in cyborg.active_agents:
            actions[agent] = random.randint(0, len(cyborg.get_action_space(agent))-1)

        obs, rews, dones, infos = cyborg.step(actions)
        for agent in cyborg.active_agents:
                assert cyborg.get_last_actions(agent) != 'InvalidAction'

#test reward bug 
def test_equal_reward():
    sg = DroneSwarmScenarioGenerator(num_drones=17, max_length_data_links=1000, starting_num_red=0)
    cyborg_raw = CybORG(scenario_generator=sg, seed=123)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()

    rews_tt = {}
    for i in range(10):
        actions = {}
        for agent in cyborg.agents:
            actions[agent] = random.randint(0,len(cyborg.get_action_space(agent))-1)

        obs, rews, dones, infos = cyborg.step(actions)
        rews_tt[i] = rews

    for i in rews_tt.keys():
        assert len(set(rews_tt[1].values())) == 1


def test_red_exploit_indirect():
    sg = DroneSwarmScenarioGenerator(num_drones=3, starting_num_red=1, max_length_data_links=7, starting_positions=np.array([np.array([5, 5]),np.array([5, 10]),np.array([5, 15])]), agent_to_drone_mapping={0: 'red', 1:'blue', 2:'blue'}, default_red_agent=SleepAgent, red_internal_only=False)
    cyborg_raw = CybORG(scenario_generator=sg, seed=AlwaysTrueGenerator())
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    red_agent = 'red_agent_0'
    assert red_agent in cyborg.active_agents
    blue_agent = 'blue_agent_1'
    assert blue_agent in cyborg.active_agents
    target_agent = 'blue_agent_2'
    assert target_agent in cyborg.active_agents

    target_obs = cyborg.env.get_observation(target_agent)
    target_obs = [obs for obs in target_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    target_host = target_obs['System info']['Hostname']
    target_ip = target_obs['Interface'][0]['IP Address']
    assert cyborg.get_observation(red_agent)[17] == 0, cyborg.get_observation(red_agent)
    results = cyborg.env.step(agent=red_agent,
                          action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    assert cyborg.get_observation(red_agent)[17] == 1, cyborg.get_observation(red_agent)
    assert cyborg.get_observation(red_agent)[0] == 0
    # check that blue agent detected attack
    blue_obs = cyborg.get_observation(blue_agent)
    assert blue_obs[5] == 1

def test_blue_retake_on_red():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=100000, starting_num_red=1, red_spawn_rate=0,
                                    starting_positions=[np.array([0, 0]), np.array([1,1])])
    cyborg_raw = CybORG(scenario_generator=sg, seed=110)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()
    actions = {}

    if cyborg.active_agents[0] == 'blue_agent_0':
        agent = cyborg.active_agents[0]
        actions[cyborg.active_agents[0]]=1
        own_id = 0
        id = 1
    else:
        agent = cyborg.active_agents[0]
        actions[cyborg.active_agents[0]]=0
        own_id = 1
        id = 0


    assert len(cyborg.active_agents) == 1
    # get position before step because obs returns old position
    pos = {h: [max(int(p), 0) for p in v.position] for h, v in cyborg.unwrapped.environment_controller.state.hosts.items()}

    obs, rews, dones, infos = cyborg.step(actions)

    # action succeeded
    assert obs[agent][0] == 0
    # no blocks
    assert all(obs[agent][1:3] == [0,0])
    # no malicious host activity
    assert obs[agent][3] == 0
    # malicious network activity
    assert all(obs[agent][4:6] == [0,0])
    # drone position
    assert all(obs[agent][6:8] == pos[f"drone_{own_id}"])
    # other drone id
    assert obs[agent][8] == id
    # other drone position after movement
    assert all(obs[agent][9:11] == pos[f"drone_{id}"])
    # no new session on host
    assert obs[agent][11] == 0
    assert len(obs[agent]) == 12
    assert len(cyborg.active_agents) == 2


def test_action_space():
    sg = DroneSwarmScenarioGenerator(num_drones=2, starting_num_red=1)
    cyborg_raw = CybORG(scenario_generator=sg, seed=123)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()

    for i in range(cyborg.action_space):
        actions = {}
        for j in range(len(cyborg.active_agents)):
            actions[cyborg.active_agents[j]] = i

        obs, rews, dones, infos = cyborg.step(actions)

        if i == 0:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'RetakeControl drone 0')
        elif i == 1:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'RetakeControl drone 1')
        elif i == 2:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'RemoveOtherSessions blue_agent_0')
        elif i == 3:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'BlockTraffic drone 0')
        elif i == 4:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'BlockTraffic drone 0')
        elif i == 5:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'AllowTraffic drone 0')
        elif i == 6:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'AllowTraffic drone 0')
        elif i == 7:
            assert (cyborg.get_last_action(cyborg.active_agents[0]) == 'Sleep')

def test_blue_remove_on_itself_no_red():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=100000, starting_num_red=0, red_spawn_rate=0,
                                    starting_positions=[np.array([0, 0]), np.array([1,1])])
    cyborg_raw = CybORG(scenario_generator=sg, seed=110)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()
    actions = {}

    for i in range(len(cyborg.active_agents)):
        actions[cyborg.active_agents[i]] = 2

    assert len(cyborg.active_agents) == 2

    obs, rews, dones, infos = cyborg.step(actions)

    assert obs[cyborg.active_agents[i]][0] == 2
    assert len(cyborg.active_agents) == 2

def test_blue_remove_on_red():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=100000, starting_num_red=1, red_spawn_rate=0,
                                    starting_positions=[np.array([0, 0]), np.array([1,1])])
    cyborg_raw = CybORG(scenario_generator=sg, seed=110)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()
    actions = {}
    agent = cyborg.active_agents[0]
    own_id = int(agent.split('_')[-1])
    other_id = (own_id + 1) % 2
    actions[agent] = 2

    assert len(cyborg.active_agents) == 1
    # get position before step because obs returns old position
    pos = {h: [max(int(p), 0) for p in v.position] for h, v in cyborg.unwrapped.environment_controller.state.hosts.items()}

    obs, rews, dones, infos = cyborg.step(actions)

    # action failed
    assert obs[agent][0] == 2
    # no blocks
    assert all(obs[agent][1:3] == [0,0])
    # no malicious host activity
    assert obs[agent][3] == 0
    # malicious network activity
    assert all(obs[agent][4:6] == [0,0])
    # drone position
    assert all(obs[agent][6:8] == pos[f"drone_{own_id}"])
    # other drone id
    assert obs[agent][8] == other_id
    # other drone position
    assert all(obs[agent][9:11] == pos[f"drone_{other_id}"])
    # no new session on host
    assert obs[agent][11] == 0
    assert len(obs[agent]) == 12

    assert len(cyborg.active_agents) == 1



def test_blue_retake_on_blue():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=100000, starting_num_red=0, red_spawn_rate=0,
                                    starting_positions=[np.array([0, 0]), np.array([1,1])])
    cyborg_raw = CybORG(scenario_generator=sg, seed=110)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()
    actions = {}
    actions['blue_agent_0']=1
    actions['blue_agent_1']=0

    assert len(cyborg.active_agents) == 2
    # get position before step because obs returns old position
    pos = {h: [max(int(p), 0) for p in v.position] for h, v in cyborg.unwrapped.environment_controller.state.hosts.items()}

    obs, rews, dones, infos = cyborg.step(actions)

    # action failed
    assert obs['blue_agent_0'][0] == 2
    # no blocks
    assert all(obs['blue_agent_0'][1:3] == [0, 0])
    # no malicious host activity
    assert obs['blue_agent_0'][3] == 0
    # malicious network activity
    assert all(obs['blue_agent_0'][4:6] == [0, 0])
    # drone position
    assert all(obs['blue_agent_0'][6:8] == pos['drone_0'])
    # other drone id
    assert obs['blue_agent_0'][8] == 1
    # other drone position
    assert all(obs['blue_agent_0'][9:11] == pos['drone_1'])
    # no new session on host
    assert obs['blue_agent_0'][11] == 0
    assert len(obs['blue_agent_0']) == 12

    # action failed
    assert obs['blue_agent_1'][0] == 2
    # no blocks
    assert all(obs['blue_agent_1'][1:3] == [0, 0])
    # no malicious host activity
    assert obs['blue_agent_1'][3] == 0
    # malicious network activity
    assert all(obs['blue_agent_1'][4:6] == [0, 0])
    # drone position
    assert all(obs['blue_agent_1'][6:8] == pos['drone_1'])
    # other drone id
    assert obs['blue_agent_1'][8] == 0
    # other drone position
    assert all(obs['blue_agent_1'][9:11] == pos['drone_0'])
    # no new session on host
    assert obs['blue_agent_1'][11] == 0
    assert len(obs['blue_agent_1']) == 12

    assert len(cyborg.active_agents) == 2


#test blocked IP bug
def test_block_and_check_IP():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=100000, starting_num_red=0, red_spawn_rate=0,
                                    starting_positions=[np.array([0, 0]), np.array([1,1])])
    cyborg_raw = CybORG(scenario_generator=sg, seed=110)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()

    actions = {}
    for i in range(2):
        count = 0
        for agent in cyborg.active_agents:
            actions[agent] = 4 - count
            count += 1

        # get position before step because obs returns old position
        pos = {h: [max(int(p), 0) for p in v.position] for h, v in
               cyborg.unwrapped.environment_controller.state.hosts.items()}

        obs, rews, dones, infos = cyborg.step(actions)

        # action success until second attempt then fail
        assert obs['blue_agent_0'][0] == 0 if i == 0 else 2
        # block against other drone
        assert all(obs['blue_agent_0'][1:3] == [0, 1])
        # no malicious host activity
        assert obs['blue_agent_0'][3] == 0
        # malicious network activity found because green is blocked
        assert all(obs['blue_agent_0'][4:6] == [0, 0]) if i == 0 else all(obs['blue_agent_0'][4:6] == [0, 1])
        # drone position
        assert all(obs['blue_agent_0'][6:8] == pos["drone_0"])
        # other drone id
        assert obs['blue_agent_0'][8] == 1
        # other drone position
        assert all(obs['blue_agent_0'][9:11] == pos["drone_1"])
        # no new session on host
        assert obs['blue_agent_0'][11] == 0
        assert len(obs['blue_agent_0']) == 12

        # action success until second attempt then fail
        assert obs['blue_agent_1'][0] == 0 if i == 0 else 2
        # block against other drone
        assert all(obs['blue_agent_1'][1:3] == [1, 0])
        # no malicious host activity
        assert obs['blue_agent_1'][3] == 0
        # malicious network activity
        assert all(obs['blue_agent_0'][4:6] == [0, 0]) if i == 0 else all(obs['blue_agent_0'][4:6] == [0, 1])
        # drone position
        assert all(obs['blue_agent_1'][6:8] == pos["drone_1"])
        # other drone id
        assert obs['blue_agent_1'][8] == 0
        # other drone position
        assert all(obs['blue_agent_1'][9:11] == pos["drone_0"])
        # no new session on host
        assert obs['blue_agent_1'][11] == 0
        assert len(obs['blue_agent_1']) == 12

#test missing obs
def test_blue_observes_red_network():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=100000, starting_num_red=1, red_spawn_rate=0,
                                    starting_positions=[np.array([0, 0]), np.array([1,1])], default_red_agent=SleepAgent)
    cyborg_raw = CybORG(scenario_generator=sg, seed=110)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()

    actions = {}
    # first block the other drone
    assert 'blue_agent_0' in cyborg.active_agents
    actions['blue_agent_0'] = 4
    obs, rews, dones, infos = cyborg.step(actions)

    # action success until second attempt then fail
    assert obs['blue_agent_0'][0] == 0
    # block against other drone
    assert all(obs['blue_agent_0'][1:3] == [0, 1])
    # no malicious host activity
    assert obs['blue_agent_0'][3] == 0
    # malicious network activity
    assert all(obs['blue_agent_0'][4:6] == [0, 0])
    # drone position
    assert all(obs['blue_agent_0'][6:8] == [0, 0])
    # other drone id
    assert obs['blue_agent_0'][8] == 1
    # other drone position
    assert all(obs['blue_agent_0'][9:11] == [1, 0])
    # no new session on host
    assert obs['blue_agent_0'][11] == 0
    assert len(obs['blue_agent_0']) == 12

    cyborg.unwrapped.step(agent='red_agent_1', action=ExploitDroneVulnerability(agent='red_agent_1', session=0,
                                                                                ip_address=cyborg.unwrapped.get_ip_map()['drone_0']))

    obs = cyborg.get_observation('blue_agent_0')

    # action second attempt fail
    assert obs[0] == 1
    # block against other drone
    assert all(obs[1:3] == [0, 1])
    # no malicious host activity
    assert obs[3] == 0
    # malicious network activity
    assert all(obs[4:6] == [0, 1])
    # drone position
    assert all(obs[6:8] == [0, 0])
    # other drone id
    assert obs[8] == 1
    # other drone position
    assert all(obs[9:11] == [1, 1])
    # no new session on host
    assert obs[11] == 0
    assert len(obs) == 12

#test missing obs
def test_blue_observes_red():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=100000, starting_num_red=1, red_spawn_rate=0,
                                    starting_positions=[np.array([0, 0]), np.array([1,1])], default_red_agent=SleepAgent)
    cyborg_raw = CybORG(scenario_generator=sg, seed=110)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    cyborg.reset()
    blue_agent_num = 0
    red_agent_num = 1
    assert f'blue_agent_{blue_agent_num}' in cyborg.active_agents
    action = ExploitDroneVulnerability(agent=f'red_agent_{red_agent_num}', session=0,
                                                                                ip_address=cyborg.unwrapped.get_ip_map()[f'drone_{blue_agent_num}'])
    action.detection_rate = 10.
    cyborg.unwrapped.step(agent=f'red_agent_{red_agent_num}', action=action)

    obs = cyborg.get_observation(f'blue_agent_{blue_agent_num}')

    # action second attempt fail
    assert obs[0] == 1
    # block against other drone
    assert all(obs[1:3] == [0, 0])
    # no malicious host activity
    assert obs[3] == 0
    # malicious network activity
    assert all(obs[4:6] == [0, 1])
    # drone position
    assert all(obs[6:8] == [0, 0])
    # other drone id
    assert obs[8] == 1
    # other drone position
    assert all(obs[9:11] == [1, 0])
    # no new session on host
    assert obs[11] == 0
    assert len(obs) == 12


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
        assert isinstance(create_wrapped_cyborg.action_space(agent), spaces.Discrete)
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
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    for agent in cyborg.agents:
        obs = cyborg.get_observation(agent)
        assert cyborg.observation_space(agent).contains(obs)


def test_invalid_positions_drones():
    sg = DroneSwarmScenarioGenerator(num_drones=2, max_length_data_links=10000,
                                     starting_positions=[np.array([-1, -1]), np.array([101, 101])])
    cyborg_raw = CybORG(scenario_generator=sg)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
    for agent in cyborg.agents:
        obs = cyborg.get_observation(agent)
        assert cyborg.observation_space(agent).contains(obs)


def test_active_agent_in_observation():
    sg = DroneSwarmScenarioGenerator(num_drones=20, max_length_data_links=10, starting_num_red=0)
    cyborg_raw = CybORG(scenario_generator=sg, seed=123)
    cyborg = PettingZooParallelWrapper(env=cyborg_raw)
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

@pytest.mark.parametrize('num_drones', [2,10,18,25])
@pytest.mark.parametrize('wrapper', [PettingZooParallelWrapper, AgentCommsPettingZooParallelWrapper, ActionsCommsPettingZooParallelWrapper, ObsCommsPettingZooParallelWrapper])
def test_observation(num_drones, wrapper):
    sg = DroneSwarmScenarioGenerator(num_drones=num_drones)
    cyborg = wrapper(CybORG(scenario_generator=sg, seed=123))
    cyborg.reset()
    for i in range(10):
        for j in range(600):
            obs, rew, dones, infos = cyborg.step({agent: cyborg.action_space(agent).sample() for agent in cyborg.agents})
            for agent in cyborg.agents:
                if type(cyborg) == PettingZooParallelWrapper:
                    assert len(obs[agent]) == (num_drones*6)
                elif type(cyborg) == ObsCommsPettingZooParallelWrapper:
                    assert len(obs[agent]) == (num_drones*22)
                else:
                    assert len(obs[agent]) == (num_drones*7)
            if any(dones.values()) or len(cyborg.agents) == 0:
                assert len(obs) > 0
                assert len(rew) > 0
                assert len(dones) > 0
                assert all(dones)
                if j < 499:
                    assert list(rew.values())[0] == - (500-j) * num_drones
                break
            assert j <= 500
        cyborg.reset()
