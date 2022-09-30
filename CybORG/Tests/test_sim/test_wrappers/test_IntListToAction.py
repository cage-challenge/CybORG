import inspect
import random

from CybORG import CybORG
from CybORG.Agents.Wrappers.IntListToAction import IntListToActionWrapper
from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator


def test_step_zeroes(create_cyborg_sim):
    agent = 'Red'
    cyborg = IntListToActionWrapper(create_cyborg_sim)
    action_space = cyborg.get_action_space(agent)
    assert type(action_space) is list
    for element in action_space:
        assert type(element) is int
    cyborg.step(agent, [0]*len(action_space))


def test_step_random():
    agent = 'Red'
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1.yaml'
    sg = FileReaderScenarioGenerator(path)
    for i in range(100):
        cyborg = IntListToActionWrapper(CybORG(scenario_generator=sg))
        action_space = cyborg.get_action_space(agent)

        action = []
        for a in action_space:
            if a > 0:
                action.append(random.choice(range(a)))
            else:
                action.append(0)
        cyborg.step(agent, action)
