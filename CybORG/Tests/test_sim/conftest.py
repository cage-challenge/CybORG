import inspect

import pytest

from CybORG import CybORG
from CybORG.Agents import B_lineAgent
from CybORG.Agents.Wrappers import OpenAIGymWrapper, EnumActionWrapper, FixedFlatWrapper
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Agents.Wrappers.CommsPettingZooParallelWrapper import AgentCommsPettingZooParallelWrapper, ActionsCommsPettingZooParallelWrapper, ObsCommsPettingZooParallelWrapper
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator
from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator


@pytest.fixture(scope="function", params=['Scenario1', 'Scenario1b', 'Scenario2'])
def create_cyborg_sim(request):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/{request.param}.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(scenario_generator=sg, seed=123)
    return cyborg


@pytest.fixture()
def cyborg_scenario1():
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1.yaml'
    sg = FileReaderScenarioGenerator(path)
    return CybORG(scenario_generator=sg)


@pytest.fixture()
def cyborg_scenario1_state(cyborg_scenario1):
    cyborg = cyborg_scenario1
    state = cyborg.environment_controller.state
    return state


@pytest.fixture
def cyborg_scenario1b(seed=1):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(scenario_generator=sg, seed=seed)
    return cyborg


@pytest.fixture
def cyborg_scenario1b_bline(seed=1):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(sg, agents={'Red': B_lineAgent()}, seed=seed)
    return cyborg


@pytest.fixture(scope="function", params=['Red', 'Blue'])
def open_ai_wrapped_cyborg(create_cyborg_sim, request):
    cyborg = create_cyborg_sim
    if str(cyborg.scenario_generator).split('/')[-1].rstrip('.yaml') == 'Scenario1' and request.param == 'Blue':
        pytest.skip('Blue agent not operational on scenario1')
    cyborg = OpenAIGymWrapper(agent_name=request.param,
                              env=FixedFlatWrapper(cyborg))
    return cyborg


@pytest.fixture(scope="function")
def cyborg_drone_scenario():
    sg = DroneSwarmScenarioGenerator()
    cyborg = CybORG(scenario_generator=sg)
    return cyborg


@pytest.fixture(scope="function", params=[PettingZooParallelWrapper, AgentCommsPettingZooParallelWrapper, ActionsCommsPettingZooParallelWrapper, ObsCommsPettingZooParallelWrapper])
def pettingzoo_parallel_wrapped_cyborg(cyborg_drone_scenario, request):
    cyborg = cyborg_drone_scenario
    cyborg = request.param(env=cyborg)
    return cyborg
# TODO add in autouse cyborg reset function
