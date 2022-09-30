import inspect

from CybORG import CybORG
from CybORG.Agents import SleepAgent
from CybORG.Agents.SimpleAgents.BlueReactAgent import BlueReactRemoveAgent, BlueReactRestoreAgent

from CybORG.Agents.SimpleAgents.Meander import RedMeanderAgent
from CybORG.Shared.Actions import Impact
from CybORG.Shared.Actions import Restore
import pytest

@pytest.mark.skip
def test_meander_agent_step():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + f'/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim', agents={'Red': RedMeanderAgent})
    action_space = cyborg.get_action_space(agent='Red')
    session = list(action_space['session'].keys())[0]
    reward = 0
    for i in range(50):
        result = cyborg.step(agent='Red')
        if i != 17:
            assert result.observation['success'] == True, f'Step: {i}, Action: {result.action}'
        else:
            # defender cannot be exploited
            assert result.observation['success'] == False, f'Step: {i}, Action: {result.action}'
        if i >= 41:
            assert type(result.action) == Impact
            assert result.action.agent == 'Red'
            assert result.action.session == session
            assert result.action.hostname == 'Op_Server0'
            if i ==41:
                reward +=10
        elif i in [8, 30, 32, 34, 35, 38, 40]:
            reward +=0.1
        elif i in [12, 19, 21]:
            reward +=1
        elif i in [24]:
            reward +=1
        assert result.reward == round(reward, 1), f'error for step {i} action {result.action}'
    cyborg.reset()
    reward = 0
    for i in range(50):
        result = cyborg.step(agent='Red')
        if i != 17:
            assert result.observation['success'] == True, f'Step: {i}, Action: {result.action}'
        else:
            # defender cannot be exploited
            assert result.observation['success'] == False, f'Step: {i}, Action: {result.action}'
        if i >= 41:
            assert type(result.action) == Impact
            assert result.action.agent == 'Red'
            assert result.action.session == session
            assert result.action.hostname == 'Op_Server0'
            if i == 41:
                reward += 10
        elif i in [8, 30, 32, 34, 35, 38, 40]:
            reward += 0.1
        elif i in [12, 19, 21]:
            reward += 1
        elif i in [24]:
            reward += 1
        assert result.reward == round(reward, 1), f'error for step {i} action {result.action}'


@pytest.mark.parametrize('blue_agent', [BlueReactRemoveAgent, BlueReactRestoreAgent, SleepAgent])
def test_meander_vs_blue_agent_start(blue_agent):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + f'/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim', agents={'Red': RedMeanderAgent, 'Blue': blue_agent})
    cyborg.start(100)
    cyborg.reset()
    cyborg.start(100)


@pytest.mark.skip
def test_meander_vs_react_remove_agent_step():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + f'/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim', agents={'Red': RedMeanderAgent, 'Blue': BlueReactRemoveAgent})
    cyborg.set_seed(1)
    for i in range(100):
        result = cyborg.step(agent='Red')
        if i in list(range(21, 100)) + [17]:
            assert result.observation['success'] == False, f'Successful action {result.action} for step {i}'
        else:
            assert result.observation['success'] == True, f'Unsuccessful action {result.action} for step {i}'
        if i > 100:
            assert result.reward == 10.
    cyborg.reset()
    cyborg.set_seed(1)
    for i in range(100):
        result = cyborg.step(agent='Red')
        if i in list(range(21, 100)) + [17]:
            assert result.observation['success'] == False, f'Successful action {result.action} for step {i}'
        else:
            assert result.observation['success'] == True, f'Unsuccessful action {result.action} for step {i}'
        if i > 100:
            assert result.reward == 10.

@pytest.mark.skip
def test_meander_vs_react_restore_agent_step():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + f'/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim', agents={'Red': RedMeanderAgent, 'Blue': BlueReactRestoreAgent})
    cyborg.set_seed(1)
    for i in range(150):
        result = cyborg.step(agent='Red')
        if i in [11] + list(range(14, 150)):
            assert result.observation['success'] == False, f'Successful action {result.action} for step {i}'
        else:
            assert result.observation['success'] == True, f'Unsuccessful action {result.action} for step {i}'
    cyborg.reset()
    for i in range(150):
        result = cyborg.step(agent='Red')
        if i in [11] + list(range(14, 150)):
            assert result.observation['success'] == False, f'Successful action {result.action} for step {i}'
        else:
            assert result.observation['success'] == True, f'Unsuccessful action {result.action} for step {i}'

@pytest.mark.skip()
def test_meander_resilience():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    env = CybORG(path,'sim')

    agent = RedMeanderAgent()

    results = env.reset('Red')
    obs = results.observation
    action_space = results.action_space

    # Meander does its thing
    for i in range(46):
        action = agent.get_action(obs,action_space)
        results = env.step(action=action,agent='Red')
        obs = results.observation
        action_space = results.action_space

    # Blue wipes out Red
    action = Restore(hostname='Op_Server0',session=0,agent='Blue')
    env.step(action=action,agent='Blue')

    action = Restore(hostname='Enterprise2',session=0,agent='Blue')
    env.step(action=action,agent='Blue')

    action = Restore(hostname='Enterprise1',session=0,agent='Blue')
    env.step(action=action,agent='Blue')

    action = Restore(hostname='Enterprise0',session=0,agent='Blue')
    env.step(action=action,agent='Blue')

    obs = env.get_observation('Red')

    # Meander recovers its position
    for i in range(12):
        action = agent.get_action(obs,action_space)
        results = env.step(action=action,agent='Red')
        obs = results.observation
        action_space = results.action_space
        # Should fail on first few steps, but then recover
        # 0->3 actions are impact OpServer, then priv esc on Enterprise0-2
        # action 8 is priv esc on OpServer
        if i > 4 and i != 8:
            assert obs['success'] == True, f'failing on step {i} with action {action}'
