import pytest

from CybORG.Agents import DroneRedAgent
from CybORG.Tests.test_sim.sim_fixtures import create_cyborg

SCENARIO = 'Scenario3'


@pytest.fixture(scope='function')
def cyborg():
    return create_cyborg(SCENARIO)

@pytest.fixture(scope='function')
def agent_name(cyborg):
    red_agents = [x for x in cyborg.active_agents if 'red' in x]

    return red_agents[0]

@pytest.fixture(scope='function')
def agent(agent_name):
    return DroneRedAgent(agent_name)

@pytest.fixture(scope='function')
def observations(agent, cyborg):
    observations= []
    obs = cyborg.get_observation(agent.name)
    action_space = cyborg.get_action_space(agent.name)
    for i in range(10):
        action = agent.get_action(obs, action_space)
        results = cyborg.step(action=action, agent=agent.name)
        obs = results.observation
        action_space = results.action_space
        
        observations.append(results.observation)

    return observations


def test_DroneRedAgent_successes(observations):
    successes = [obs['success'] for obs in observations]

    assert all(successes)
    



