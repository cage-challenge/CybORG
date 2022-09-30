

from CybORG.Agents import BaseAgent
from CybORG.Shared import Scenario
from CybORG.Simulator.Actions.Action import lo
from CybORG.Shared.RewardCalculator import RewardCalculator


class ScenarioGenerator:
    """
    The ScenarioGenerator class is an abstract class that defines the interface for other ScenarioGenerator classes
    Functions:
    - create_scenario
        creates a scenario object that can be used to initialise the state
    - validate_scenario
        takes in a scenario object and raises errors if the scenario is misconfigured or missing important information
    """

    def __init__(self):
        self.update_each_step = True

    def create_scenario(self, np_random) -> Scenario:
        raise NotImplementedError

    def determine_done(self, env_controller):
        return False

    def validate_scenario(self, scenario: Scenario):
        # check that all agents are assigned to a team
        for name, data in scenario.agents.items():
            assert data.team is not None
            assert data.team in scenario.get_teams()
            assert name in scenario.get_team_info(data.team)['agents']
            for calc in scenario.get_team_info(data.team)['calcs'].values():
                assert issubclass(type(calc), RewardCalculator)
            assert issubclass(type(data.agent_type), BaseAgent), f"agent: {name}, type {data.agent_type}"

        for hostname, host_info in scenario.hosts.items():
            assert "OSType" in host_info.system_info
            assert "OSDistribution" in host_info.system_info
            assert "OSVersion" in host_info.system_info
            assert "Architecture" in host_info.system_info

            # cannot have both wired and wireless interfaces currently because movement away from wireless will disconnect wired as well
            interface_type = None
            for interface in host_info.interface_info:
                if 'type' in interface:
                    if interface_type is None:
                        interface_type = interface['type']
                    else:
                        if interface_type != interface['type']:
                            raise ValueError('CybORG does not currently support multiple types of interfaces on a single host')



    def __str__(self):
        return "BaseScenarioGenerator"
