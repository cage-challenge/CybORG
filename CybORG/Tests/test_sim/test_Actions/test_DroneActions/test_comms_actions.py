from random import choices, choice

import numpy as np

from CybORG import CybORG
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator


def test_comms():
    # create env with large bandwidth and fully connected
    sg = DroneSwarmScenarioGenerator(max_length_data_links=10000, data_link_bandwidth=1000)
    cyborg = CybORG(sg, seed=123)
    # get two random agents
    agent = cyborg.np_random.choice([agent for agent in cyborg.active_agents], 2, replace=False)
    # send random message from each agent
    message1 = cyborg.get_message_space(agent[0]).sample()
    message2 = cyborg.get_message_space(agent[1]).sample()
    messages = {agent[0]: message1, agent[1]: message2}
    observations, rewards, dones, info = cyborg.parallel_step(messages=messages)
    # check that other agent recieved message
    assert any([all(a == message1) for a in observations[agent[1]].get('message')])
    assert any([all(a == message2) for a in observations[agent[1]].get('message')])
    assert any([all(a == message1) for a in observations[agent[0]].get('message')])
    assert any([all(a == message2) for a in observations[agent[0]].get('message')])

# Bandwidth will not affect comms
# def test_dropped_comms():
#     # create env with small bandwidth and fully connected
#     sg = DroneSwarmScenarioGenerator(max_length_data_links=10000, data_link_bandwidth=1)
#     cyborg = CybORG(sg)    # get one random blue agent and one random red agent
#     blue_agent = choice([agent for agent in cyborg.active_agents if 'blue' in agent.lower()])
#     red_agent = choice([agent for agent in cyborg.active_agents if 'red' in agent.lower()])
#     # TODO: get overload action to blue agent
#     overload_action = 0
#
#     # send random message from each agent
#     message1 = cyborg.get_message_space(blue_agent).sample()
#     message2 = cyborg.get_message_space(red_agent).sample()
#     messages = {blue_agent: message1, red_agent: message2}
#     actions = {red_agent: overload_action}
#     observations, rewards, dones, info = cyborg.parallel_step(messages=messages, actions=actions)
#
#     # check that other agent did not recieve message
#     assert any([all(a == message1) for a in observations[blue_agent].get('message')])
#     assert not any([all(a == message2) for a in observations[blue_agent].get('message')])
#     assert any([all(a == message1) for a in observations[red_agent].get('message')])
#     assert not any([all(a == message2) for a in observations[red_agent].get('message')])

def test_comms_no_route():
    # create env with large bandwidth and no connections
    sg = DroneSwarmScenarioGenerator(max_length_data_links=1, num_drones=2, data_link_bandwidth=1000, starting_positions=[np.array([0,0]), np.array([100,100])], red_internal_only = False)
    cyborg = CybORG(sg, seed=123)
    # get two random agents
    agent = cyborg.np_random.choice([agent for agent in cyborg.active_agents], 2, replace=False)

    # send random message from each agent
    message1 = cyborg.get_message_space(agent[0]).sample()
    message2 = cyborg.get_message_space(agent[1]).sample()
    messages = {agent[0]: message1, agent[1]: message2}
    observations, rewards, dones, info = cyborg.parallel_step(messages=messages)
    # check that other agent recieved message
    assert not any([all(a == message1) for a in observations[agent[1]].get('message')])
    assert any([all(a == message2) for a in observations[agent[1]].get('message')])
    assert any([all(a == message1) for a in observations[agent[0]].get('message')])
    assert not any([all(a == message2) for a in observations[agent[0]].get('message')])
