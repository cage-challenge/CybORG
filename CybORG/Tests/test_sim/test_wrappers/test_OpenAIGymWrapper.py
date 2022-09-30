import pytest
import inspect
from gym import spaces
from CybORG import CybORG
from CybORG.Agents.Wrappers.OpenAIGymWrapper import OpenAIGymWrapper
from CybORG.Agents.Wrappers.FixedFlatWrapper import FixedFlatWrapper
from CybORG.Agents.Wrappers.EnumActionWrapper import EnumActionWrapper
from CybORG.Agents.Wrappers import BlueTableWrapper
from CybORG.Agents import BlueMonitorAgent, B_lineAgent 


def test_steps():
    agent = 'Red'
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = OpenAIGymWrapper(agent_name=agent,
                              env=FixedFlatWrapper(EnumActionWrapper(CybORG(path, 'sim'))))
    cyborg.reset()
    action = cyborg.action_space.sample()
    obs, reward, done, info = cyborg.step(action)

    # assert isinstance(obs, object) # Redundant because everything in python is an object
    assert obs is not None
    assert isinstance(reward, float)
    assert isinstance(done, bool)
    assert isinstance(info, dict)

    # Check spaces
    assert isinstance(cyborg.action_space, spaces.Discrete)
    assert cyborg.action_space.n == 56

    assert isinstance(cyborg.observation_space, spaces.Box)
    # TODO: Replace 14116 with the maximum observation length variable
    # Make sure the length of the observation does not exceed the maximum observation.
    assert cyborg.observation_space.shape == (11293,)


@pytest.mark.skip("Deprecated")
def test_steps_multi_discrete():
    agent = 'Red'
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = OpenAIGymWrapper(agent_name=agent,
                              env=FixedFlatWrapper(EnumActionWrapper(CybORG(path, 'sim'))))
    cyborg.reset()
    action = cyborg.action_space.sample()
    obs, reward, done, info = cyborg.step(action)

    # assert isinstance(obs, object) # Redundant because everything in python is an object
    assert obs is not None
    assert isinstance(reward, float)
    assert isinstance(done, bool)
    assert isinstance(info, dict)

    # Check spaces
    assert isinstance(cyborg.action_space, spaces.MultiDiscrete)
    assert cyborg.action_space.shape[0] == 4
    assert (cyborg.action_space.nvec == [6, 3, 13, 13]).all()

    assert isinstance(cyborg.observation_space, spaces.Box)
    # TODO: Replace 14116 with the maximum observation length variable
    # Make sure the length of the observation does not exceed the maximum observation.
    assert cyborg.observation_space.shape == (11293,)

def test_steps_random():
    agent = 'Red'
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = OpenAIGymWrapper(agent_name=agent, env=FixedFlatWrapper(EnumActionWrapper(CybORG(path, 'sim'))))
    cyborg.reset()
    original_action = cyborg.action_space.n
    for i in range(100):
        # Assert the action space is the original action space.
        assert cyborg.action_space.n == original_action
        # Assert the observation remains within the set max length
        assert cyborg.observation_space.shape <= (14116,)

    MAX_STEPS_PER_GAME = 20
    MAX_EPS = 100
    for i in range(MAX_EPS):
        for j in range(MAX_STEPS_PER_GAME):
            action = cyborg.action_space.sample()
            obs, rew, done, info = cyborg.step(action)
            if done or j == MAX_STEPS_PER_GAME-1:
                break
        cyborg.reset()

@pytest.mark.skip("Deprecated")
def test_steps_random_multi_discrete():
    agent = 'Red'
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = OpenAIGymWrapper(agent_name=agent, env=FixedFlatWrapper(EnumActionWrapper(CybORG(path, 'sim'))))
    cyborg.reset()
    original_action = cyborg.action_space.nvec
    for i in range(100):
        # Assert the action space is the original action space.
        assert (cyborg.action_space.nvec == original_action).all()
        # Assert the observation remains within the set max length
        assert cyborg.observation_space.shape <= (14116,)

    MAX_STEPS_PER_GAME = 20
    MAX_EPS = 100
    for i in range(MAX_EPS):
        for j in range(MAX_STEPS_PER_GAME):
            action = cyborg.action_space.sample()
            obs, rew, done, info = cyborg.step(action)
            if done or j == MAX_STEPS_PER_GAME-1:
                break
        cyborg.reset()

@pytest.fixture(params=['Red','Blue'])
def cyborg(request,agents = {'Blue':BlueMonitorAgent,'Red':B_lineAgent},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    env = FixedFlatWrapper(EnumActionWrapper(CybORG(path, 'sim', agents=agents)))
    cyborg = OpenAIGymWrapper(env=env,agent_name=request.param)
    cyborg.set_seed(seed)
    return cyborg

def test_get_attr(cyborg):
    for attribute in ['get_observation','get_action_space','get_last_action','get_ip_map',
            'get_rewards', 'get_agent_state']:
        assert cyborg.get_attr(attribute) == cyborg.env.get_attr(attribute)

def test_get_observation(cyborg):
    step_obs = cyborg.reset()
    method_obs = cyborg.get_observation(cyborg.agent_name)
    assert all(step_obs == method_obs)

    step_obs, reward, done, info = cyborg.step()
    method_obs = cyborg.get_observation(cyborg.agent_name)
    assert all(step_obs == method_obs)

def test_get_agent_state(cyborg):
    cyborg.reset()
    cyborg.step()
    assert cyborg.get_agent_state('True') == cyborg.get_attr('get_agent_state')('True')
    assert cyborg.get_agent_state('Red') == cyborg.get_attr('get_agent_state')('Red')
    assert cyborg.get_agent_state('Blue') == cyborg.get_attr('get_agent_state')('Blue')

def test_get_action_space(cyborg):
    red_space = cyborg.get_action_space(cyborg.agent)
    assert type(red_space) == int

def test_get_last_action(cyborg):
    cyborg.reset()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')
    cyborg.step()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')

def test_get_ip_map(cyborg):
    assert cyborg.get_ip_map() == cyborg.get_attr('get_ip_map')()

def test_get_rewards(cyborg):
    assert cyborg.get_rewards() == cyborg.get_attr('get_rewards')()

