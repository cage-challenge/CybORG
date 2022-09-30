import inspect

import pytest

from CybORG import CybORG
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator, FileReaderScenarioGenerator


@pytest.fixture(params=list(range(10)))
def cyborg_drone_scenario(request):
    sg = DroneSwarmScenarioGenerator(red_internal_only=False)
    return CybORG(scenario_generator=sg, seed=request.param), request.param

def test_cyborg_drone_random_seed(cyborg_drone_scenario):
    cyborg, seed = cyborg_drone_scenario
    # test same agents at all time_steps
    agents = {}
    action_type = {}
    action_target = {}
    positions = {}
    messages = {}
    action_space = {}
    for i in range(10):
        for j in range(100):
            cyborg.step()
            if j not in agents:
                agents[j] = cyborg.active_agents
                action_type[j] = [type(cyborg.get_last_action(agent)) for agent in cyborg.active_agents]
                action_target[j] = [cyborg.get_last_action(agent).ip_address for agent in cyborg.active_agents if hasattr(cyborg.get_last_action(agent),'ip_address')]
                positions[j] = [i.position for i in cyborg.environment_controller.state.hosts.values()]
                messages[j] = [cyborg.get_message_space(agent).sample() for agent in cyborg.active_agents]
                action_space[j] = [cyborg.get_action_space(agent) for agent in cyborg.active_agents]
            else:
                assert agents[j] == cyborg.active_agents, f'failed on episode {i} step {j}'
                assert action_type[j] == [type(cyborg.get_last_action(agent)) for agent in cyborg.active_agents], f'failed on episode {i} step {j}'
                assert action_target[j] == [cyborg.get_last_action(agent).ip_address for agent in cyborg.active_agents if hasattr(cyborg.get_last_action(agent),'ip_address')], f'failed on episode {i} step {j}'
                assert all([all(a == b) for a, b in zip(positions[j], [i.position for i in cyborg.environment_controller.state.hosts.values()])]), f'failed on episode {i} step {j}'
                assert all(all(a==b) for a,b in zip(messages[j], [cyborg.get_message_space(agent).sample() for agent in cyborg.active_agents]))
                assert all([(a==b) for a,b in zip(action_space[j], [cyborg.get_action_space(agent) for agent in cyborg.active_agents])])

        cyborg.reset(seed=seed)

@pytest.fixture(params=list(range(10)))
def cyborg_scenario1b(request):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    return CybORG(sg, 'sim', seed=request.param), request.param

def test_cyborg_1b_random_seed(cyborg_scenario1b):
    cyborg, seed = cyborg_scenario1b
    # test same agents at all time_steps
    agents = {}
    action_type = {}
    action_target = {}
    positions = {}
    messages = {}
    action_space = {}
    for i in range(10):
        for j in range(100):
            cyborg.step()
            if j not in agents:
                agents[j] = cyborg.active_agents
                action_type[j] = [type(cyborg.get_last_action(agent)) for agent in cyborg.active_agents]
                action_target[j] = [cyborg.get_last_action(agent).ip_address for agent in cyborg.active_agents if hasattr(cyborg.get_last_action(agent),'ip_address')]
                positions[j] = [i.position for i in cyborg.environment_controller.state.hosts.values()]
                messages[j] = [cyborg.get_message_space(agent).sample() for agent in cyborg.active_agents]
                action_space[j] = [cyborg.get_action_space(agent) for agent in cyborg.active_agents]
            else:
                assert agents[j] == cyborg.active_agents, f'failed on episode {i} step {j}'
                assert action_type[j] == [type(cyborg.get_last_action(agent)) for agent in cyborg.active_agents], f'failed on episode {i} step {j}'
                assert action_target[j] == [cyborg.get_last_action(agent).ip_address for agent in cyborg.active_agents if hasattr(cyborg.get_last_action(agent),'ip_address')], f'failed on episode {i} step {j}'
                assert all([(a==b) for a, b in zip(positions[j], [i.position for i in cyborg.environment_controller.state.hosts.values()])]), f'failed on episode {i} step {j}'
                assert all([a==b for a,b in zip(messages[j], [cyborg.get_message_space(agent).sample() for agent in cyborg.active_agents])][0])
                assert all([(a==b) for a,b in zip(action_space[j], [cyborg.get_action_space(agent) for agent in cyborg.active_agents])])

        cyborg.reset(seed=seed)

def test_cyborg_1b_random_seed_new_CybORG(cyborg_scenario1b):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(sg, 'sim', seed=123)
    agents = {}
    action_type = {}
    action_target = {}
    positions = {}
    messages = {}
    action_space = {}
    for i in range(10):
        for j in range(100):
            cyborg.step()
            if j not in agents:
                agents[j] = cyborg.active_agents
                action_type[j] = [type(cyborg.get_last_action(agent)) for agent in cyborg.active_agents]
                action_target[j] = [cyborg.get_last_action(agent).ip_address for agent in cyborg.active_agents if hasattr(cyborg.get_last_action(agent),'ip_address')]
                positions[j] = [i.position for i in cyborg.environment_controller.state.hosts.values()]
                messages[j] = [cyborg.get_message_space(agent).sample() for agent in cyborg.active_agents]
                action_space[j] = [cyborg.get_action_space(agent) for agent in cyborg.active_agents]
            else:
                assert agents[j] == cyborg.active_agents, f'failed on episode {i} step {j}'
                assert action_type[j] == [type(cyborg.get_last_action(agent)) for agent in cyborg.active_agents], f'failed on episode {i} step {j}'
                assert action_target[j] == [cyborg.get_last_action(agent).ip_address for agent in cyborg.active_agents if hasattr(cyborg.get_last_action(agent),'ip_address')], f'failed on episode {i} step {j}'
                assert all([(a==b) for a, b in zip(positions[j], [i.position for i in cyborg.environment_controller.state.hosts.values()])]), f'failed on episode {i} step {j}'
                assert all([a==b for a,b in zip(messages[j], [cyborg.get_message_space(agent).sample() for agent in cyborg.active_agents])][0])
                assert all([(a==b) for a,b in zip(action_space[j], [cyborg.get_action_space(agent) for agent in cyborg.active_agents])])

        sg = FileReaderScenarioGenerator(path)
        cyborg = CybORG(sg, 'sim', seed=123)