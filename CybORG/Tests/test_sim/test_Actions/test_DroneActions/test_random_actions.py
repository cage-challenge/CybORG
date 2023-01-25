import pytest

from CybORG import CybORG
from CybORG.Agents import RandomAgent
from CybORG.Agents.Wrappers.PettingZooParallelWrapper import PettingZooParallelWrapper
from CybORG.Agents.Wrappers.ValidationWrapper import ValidationDroneWrapper
from CybORG.Simulator.Actions import InvalidAction, Sleep
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator


@pytest.fixture(params=[lambda sg: {f'blue_agent_{agent}': RandomAgent() for agent in range(sg.num_drones)},
                        lambda sg: {f'red_agent_{agent}': RandomAgent() for agent in range(sg.num_drones)},
                        lambda sg: {f'{team}_agent_{agent}': RandomAgent() for agent in range(sg.num_drones) for team in
                                    ['red', 'blue']}])
def cyborg(request):
    sg = DroneSwarmScenarioGenerator(red_internal_only=False)
    return ValidationDroneWrapper(env=CybORG(scenario_generator=sg, agents=request.param(sg), seed=123))


def test_random_actions(cyborg):
    for j in range(10):
        actions = []
        for i in range(100):
            actions.append([])
            for agent in cyborg.active_agents:
                a = cyborg.get_last_action(agent)
                actions[i].append(a)
                if a is not None and type(a) not in (Sleep, InvalidAction):
                    assert a.agent == agent
                    if agent in cyborg.active_agents:
                        assert a.session in cyborg.env.environment_controller.state.sessions[agent], f"{agent} {j} {i}"
            cyborg.step()

            for hostname, host in cyborg.env.environment_controller.state.hosts.items():
                for agent in cyborg.env.environment_controller.agent_interfaces.keys():
                    temp = [k for k, v in cyborg.env.environment_controller.state.sessions[agent].items() if v.hostname == hostname]
                    assert temp == host.sessions[agent]
        cyborg.reset()
