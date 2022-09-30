from collections import namedtuple

import pytest

from CybORG.Shared.Enums import TrinaryEnum
from CybORG.Simulator.Actions import Sleep, InvalidAction, Action
from CybORG.Shared import Observation
from CybORG.Tests.test_sim.sim_fixtures import create_cyborg, SCENARIOS

ScenarioAgent = namedtuple('ScenarioAgent', ['scenario', 'agent'])
SCENARIO_AGENTS = [ScenarioAgent(s,a) for s in SCENARIOS for a in SCENARIOS[s]['Agents']]
    

@pytest.fixture(params = SCENARIO_AGENTS, scope='module')
def scenario_agent(request):
    # Enables us to test basic action on all agents per scenario
    # Since agents depend on the scenario, we test on each valid scenario-agent pair.
    return request.param

@pytest.fixture(scope='function')
def cyborg(scenario_agent):
    cyborg = create_cyborg(scenario_agent.scenario)
    cyborg.reset()

    return cyborg

def test_sleep_action(cyborg, scenario_agent):
    action = Sleep()
    results = cyborg.step(action=action, agent=scenario_agent.agent)

    assert results.observation == {'success': TrinaryEnum.UNKNOWN}

def test_invalid_action(cyborg, scenario_agent):
    action = InvalidAction()
    results = cyborg.step(action=action, agent=scenario_agent.agent)

    assert results.observation == {'success': TrinaryEnum.UNKNOWN}
