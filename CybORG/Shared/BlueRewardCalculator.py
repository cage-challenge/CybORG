from CybORG.Shared import Scenario
from CybORG.Shared.RedRewardCalculator import DistruptRewardCalculator, PwnRewardCalculator
from CybORG.Shared.RewardCalculator import RewardCalculator


class ConfidentialityRewardCalculator(RewardCalculator):
    # Calculate punishment for defending agent based on compromise of hosts/data
    def __init__(self, agent_name: str, scenario: Scenario):
        self.scenario = scenario
        self.adversary = scenario.get_agent_info(agent_name).adversary
        super(ConfidentialityRewardCalculator, self).__init__(agent_name)
        self.infiltrate_rc = PwnRewardCalculator(self.adversary, scenario)

    def reset(self):
        self.infiltrate_rc.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        return -self.infiltrate_rc.calculate_reward(current_state, action, agent_observations, done)


class AvailabilityRewardCalculator(RewardCalculator):
    # Calculate punishment for defending agent based on reduction in availability
    def __init__(self, agent_name: str, scenario: Scenario):
        super(AvailabilityRewardCalculator, self).__init__(agent_name)
        self.adversary = scenario.get_agent_info(agent_name).adversary
        self.disrupt_rc = DistruptRewardCalculator(self.adversary, scenario)

    def reset(self):
        self.disrupt_rc.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        return -self.disrupt_rc.calculate_reward(current_state, action, agent_observations, done)


class HybridAvailabilityConfidentialityRewardCalculator(RewardCalculator):
    # Hybrid of availability and confidentiality reward calculator
    def __init__(self, agent_name: str, scenario: Scenario):
        super(HybridAvailabilityConfidentialityRewardCalculator, self).__init__(agent_name)
        self.availability_calculator = AvailabilityRewardCalculator(agent_name, scenario)
        self.confidentiality_calculator = ConfidentialityRewardCalculator(agent_name, scenario)

    def reset(self):
        self.availability_calculator.reset()
        self.confidentiality_calculator.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        reward = self.availability_calculator.calculate_reward(current_state, action, agent_observations, done) \
                 + self.confidentiality_calculator.calculate_reward(current_state, action, agent_observations, done)
        return reward
