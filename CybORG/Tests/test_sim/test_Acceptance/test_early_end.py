import pytest

from CybORG import CybORG
from CybORG.Agents import DroneRedAgent
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator


@pytest.mark.parametrize("num_steps", [0, 1, 2, 20, 100, 1000])
def test_early_ending(num_steps):
    num_drones = 20
    sg = DroneSwarmScenarioGenerator(num_drones=num_drones, max_length_data_links=10000, maximum_steps=num_steps,
                                     default_red_agent=DroneRedAgent)
    cyborg = CybORG(scenario_generator=sg, seed=123)
    for i in range(50):
        cyborg.reset()
        for j in range(num_steps+1):
            if len(cyborg.active_agents) == 0 or j >= num_steps:
                assert cyborg.environment_controller.done
                assert cyborg.get_rewards()['Blue']['CompleteCompromise'] == -num_drones * (num_steps - j)
                break
            else:
                assert sum(cyborg.get_rewards()['Blue'].values()) <= num_drones
                assert not cyborg.environment_controller.done
            cyborg.step()
