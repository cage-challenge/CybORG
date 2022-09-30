import inspect

import pytest

from CybORG import CybORG
from CybORG.Agents.Wrappers import FixedFlatWrapper
from CybORG.Shared import Results
from CybORG.Shared.Actions.Action import Action
from CybORG.Shared.Observation import Observation


@pytest.fixture(params=['Red'])
def create_agent_interface(request):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, environment='sim')
    ec = cyborg.environment_controller
    ai = ec.agent_interfaces
    index = request.param
    return ai[index], cyborg


@pytest.mark.parametrize('observation', [Observation()])
def test_get_action(create_agent_interface, observation):
    ai, _ = create_agent_interface
    for i in range(100):
        action = ai.get_action(observation)
        assert issubclass(type(action), Action)


@pytest.mark.parametrize(['observation', 'action', 'reward', 'next_observation', 'done'], [({}, Action(), 0.5, {}, True)])
def test_train(create_agent_interface, observation, action, reward, next_observation, done):
    ai, _ = create_agent_interface
    ai.train(Results(observation=observation, done=done, reward=reward, action=action, next_observation=next_observation))


def test_reset(create_agent_interface):
    ai, _ = create_agent_interface
    ai.reset()


# TODO update test to test the flat fixed wrapper
def test_flat_numeric(create_agent_interface):
    ai, cyborg = create_agent_interface
    obs = cyborg.get_agent_state('Red')
    wrapper = FixedFlatWrapper()
    obs = wrapper.observation_change(obs)
    assert type(obs) is list
    for element in obs:
        assert type(element) is float


@pytest.mark.parametrize(['agent'], [("Red",),])
def test_fixed_numeric(agent):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = CybORG(path, 'sim')
    results = cyborg.reset(agent)
    wrapper = FixedFlatWrapper()
    obs = wrapper.observation_change(results.observation)
    for i in range(100):
        results = cyborg.step(agent)
        new_obs = wrapper.observation_change(results.observation)
        assert len(obs) == len(new_obs)
        obs = new_obs
