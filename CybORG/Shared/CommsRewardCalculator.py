from CybORG.Shared.RewardCalculator import RewardCalculator


class CommsAvailabilityRewardCalculator(RewardCalculator):
    """ Reward Calculator that returns -1 reward per action that failed for specified team"""
    def __init__(self, team: str):
        super(CommsAvailabilityRewardCalculator, self).__init__('Not Required')
        self.team = team

    def calculate_simulation_reward(self, env_controller):
        reward = 0.
        for agent in env_controller.team_assignments[self.team]:
            if env_controller.get_last_observation(agent).success == False:
                reward -= 1.
        return reward


class CompleteCompromiseRewardCalculator(RewardCalculator):
    def __init__(self, maximum_steps: int):
        super(CompleteCompromiseRewardCalculator, self).__init__('Not Required')
        self.maximum_steps = maximum_steps

    def calculate_simulation_reward(self, env_controller):
        """if done returns -1 reward per host per remaining time step
         assumes that there are no agents remaining on the specified team"""
        if env_controller.done:
            return - max(len(env_controller.state.hosts) * (self.maximum_steps - env_controller.step_count), 0.)
        else:
            return 0.

    # def calculate_green_reward(self):
    #     G_agents_states = {}
    #     for agent in green_agents:
    #         G_agents_stats[agent] = self.env.get_agent_state(agent)['success']
    #     rews = GreenAvailabilityRewardCalculator(G_agents_states, self.green_agents).calculate_reward()
    #     return rews

# class GreenConfidentialityRewardCalculator(RewardCalculator):
#     def __init__(self):
#         self.reward = 0
#
# class GreenAvailabilityRewardCalculator(RewardCalculator):
#     def __init__(self, green_agents, green_obs):
#         self.green_obs = green_obs
#         self.green_agents = green_agents
#
#     def reset(self):
#         total_reward = 0
#         return total_reward
#
#     def calculate_reward(self):
#         total_reward = 0
#         for agent in self.green_agents:
#             if self.green_obs[agent]['success'].name == 'TRUE':
#                 total_reward += 1
#             elif self.green_obs[agent]['success'].name == 'FALSE':
#                 total_reward -= 1
#             else:
#                 total_reward += 0
#
#         return total_reward
#
# class GreenIntegrityRewardCalculator(RewardCalculator):
#     def __init__(self):
#         self.reward = 0

# from collections import namedtuple

# from CybORG.Shared import Scenario
# from CybORG.Shared.RewardCalculator import RewardCalculator
# from from CybORG.Simulator.Actions.SendData import SendData # May be optional
#
# class CommsIntegrityRewardCalculator(RewardCalculator):
#     def __init__(self, agent_name: str, scenario: Scenario):
#         super(CommsIntegrityRewardCalculator, self).__init__(agent_name)
#         self.scenario = scenario
#
#     def reset(self):
#         super(CommsIntegrityRewardCalculator, self).reset()
#
#     def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
#         # Do we need to verify that agent is a green agent?
#
#         agent_action = action[agent_name]
#         if type(agent_action) is SendData:
#             if agent_observations[agent].data['success'] == True:
#                 return 5.0
#             else:
#                 return -5.0
#         return 0.0
