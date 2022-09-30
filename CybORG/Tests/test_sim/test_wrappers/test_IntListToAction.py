import inspect
import random

from CybORG import CybORG
from CybORG.Agents.Wrappers.IntListToAction import IntListToActionWrapper


def test_step_zeroes():
    agent = 'Red'
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    cyborg = IntListToActionWrapper(CybORG(path, 'sim'))
    action_space = cyborg.get_action_space(agent)
    assert type(action_space) is list
    for element in action_space:
        assert type(element) is int
    cyborg.step(agent, [0]*len(action_space))


def test_step_random():
    agent = 'Red'
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
    for i in range(100):
        cyborg = IntListToActionWrapper(CybORG(path, 'sim'))
        action_space = cyborg.get_action_space(agent)

        action = []
        for a in action_space:
            if a > 0:
                action.append(random.choice(range(a)))
            else:
                action.append(0)
        cyborg.step(agent, action)
