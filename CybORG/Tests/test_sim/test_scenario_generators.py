import inspect

import pytest
from gym.utils import seeding

from CybORG import CybORG
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator
from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator


@pytest.fixture(scope="function", params=['Scenario1', 'Scenario1b', 'Scenario2'])
def get_scenario_path(request):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/{request.param}.yaml'
    return path

# test file scenario generator
def test_file_scenario_generator(get_scenario_path):
    path = get_scenario_path
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(scenario_generator=sg)
    cyborg.step()
    cyborg.reset()

# test file scenario generator
def test_valid_file_scenario(get_scenario_path):
    path = get_scenario_path
    sg = FileReaderScenarioGenerator(path)
    np_random, seed = seeding.np_random(123)
    sg.validate_scenario(sg.create_scenario(np_random))

# test file scenario generator
def test_drone_scenario_generator():
    sg = DroneSwarmScenarioGenerator()
    cyborg = CybORG(scenario_generator=sg)
    cyborg.step()
    cyborg.reset()

# test file scenario generator
@pytest.mark.parametrize('seed', list(range(100)))
def test_valid_drone_scenario(seed):
    np_random, seed = seeding.np_random(seed)
    sg = DroneSwarmScenarioGenerator()
    sg.validate_scenario(sg.create_scenario(np_random))
