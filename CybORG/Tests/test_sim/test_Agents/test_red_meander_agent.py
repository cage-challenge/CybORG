import inspect

from CybORG import CybORG
from CybORG.Agents import SleepAgent
from CybORG.Agents.SimpleAgents.BlueReactAgent import BlueReactRemoveAgent, BlueReactRestoreAgent

from CybORG.Agents.SimpleAgents.Meander import RedMeanderAgent
from CybORG.Shared.Enums import TrinaryEnum
from CybORG.Simulator.Actions import Impact
from CybORG.Simulator.Actions import Restore
import pytest

from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator


@pytest.mark.skip
def test_meander_agent_step():
    # manually configured test for a set seed
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)

    cyborg = CybORG(sg, 'sim', agents={'Red': RedMeanderAgent()}, seed=123)
    action_space = cyborg.get_action_space(agent='Red')
    session = list(action_space['session'].keys())[0]
    reward = 0
    for i in range(50):
        result = cyborg.step(agent='Red')
        if i not in []:
            assert result.observation['success'] == True, f'Step: {i}, Action: {result.action}'
        else:
            # defender cannot be exploited
            assert result.observation['success'] == False, f'Step: {i}, Action: {result.action}'
        if i >= 30:
            assert type(result.action) == Impact
            assert result.action.agent == 'Red'
            assert result.action.session == session
            assert result.action.hostname == 'Op_Server0'
            if i == 30:
                reward += 10
        elif i in [8, 11, 14, 22]:
            reward += 0.1
        elif i in [15, 21, 24, 28]:
            reward += 1
        assert result.reward == round(reward, 1), f'error for step {i} action {result.action}'
    cyborg.reset()
    reward = 0
    for i in range(50):
        result = cyborg.step(agent='Red')
        if i not in [19]:
            assert result.observation['success'] == True, f'Step: {i}, Action: {result.action}'
        else:
            # defender cannot be exploited
            assert result.observation['success'] == False, f'Step: {i}, Action: {result.action}'
        if i >= 33:
            assert type(result.action) == Impact
            assert result.action.agent == 'Red'
            assert result.action.session == session
            assert result.action.hostname == 'Op_Server0'
            if i == 33:
                reward += 10
        elif i in [9, 12, 25]:
            reward += 0.1
        elif i in [14, 27, 29, 31]:
            reward += 1
        assert result.reward == round(reward, 1), f'error for step {i} action {result.action}'


@pytest.mark.parametrize('blue_agent', [BlueReactRemoveAgent, BlueReactRestoreAgent, SleepAgent])
def test_meander_vs_blue_agent_start(blue_agent):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(sg, 'sim', agents={'Red': RedMeanderAgent(), 'Blue': blue_agent()})
    cyborg.start(100)
    cyborg.reset()
    cyborg.start(100)


@pytest.mark.skip
def test_meander_vs_react_remove_agent_step():
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(sg, 'sim', agents={'Red': RedMeanderAgent(), 'Blue': BlueReactRemoveAgent()}, seed=1)
    fails = 0
    for i in range(100):
        result = cyborg.step(agent='Red')
        if result.observation['success'] == False:
            fails += 1
        if i > 100:
            assert result.reward == 10.

    # TODO calculate expected failure rate
    assert fails < 20
    fails = 0
    cyborg.reset(seed=123)
    for i in range(100):
        result = cyborg.step(agent='Red')
        if result.observation['success'] == False:
            fails += 1
        if i > 100:
            assert result.reward == 10.
    assert fails < 20



def test_meander_vs_react_restore_agent_step():
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(sg, 'sim', agents={'Red': RedMeanderAgent(), 'Blue': BlueReactRestoreAgent()}, seed=123)
    fails = 0
    for i in range(150):
        result = cyborg.step(agent='Red')
        if result.observation['success'] == False:
            fails += 1
    assert fails > 50
    fails = 0
    cyborg.reset(seed=123)
    for i in range(150):
        result = cyborg.step(agent='Red')
        if result.observation['success'] == False:
            fails += 1
    assert fails > 50

@pytest.mark.skip
def test_meander_resilience():
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    env = CybORG(sg, 'sim', seed=123)

    agent = RedMeanderAgent(env.np_random)

    results = env.reset('Red')
    obs = results.observation
    action_space = results.action_space

    # Meander does its thing
    for i in range(46):
        action = agent.get_action(obs, action_space)
        results = env.step(action=action, agent='Red')
        obs = results.observation
        action_space = results.action_space

    # Blue wipes out Red
    action = Restore(hostname='Op_Server0', session=0, agent='Blue')
    env.step(action=action, agent='Blue')

    action = Restore(hostname='Enterprise2', session=0, agent='Blue')
    env.step(action=action, agent='Blue')

    action = Restore(hostname='Enterprise1', session=0, agent='Blue')
    env.step(action=action, agent='Blue')

    action = Restore(hostname='Enterprise0', session=0, agent='Blue')
    env.step(action=action, agent='Blue')

    obs = env.get_observation('Red')

    # Meander recovers its position
    for i in range(12):
        action = agent.get_action(obs, action_space)
        results = env.step(action=action, agent='Red')
        obs = results.observation
        action_space = results.action_space
        # Should fail on first few steps, but then recover
        if i == 11:
            assert obs['success'] == True, f'failing on step {i} with action {action}'
