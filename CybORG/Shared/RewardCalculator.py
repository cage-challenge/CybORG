# Copyright DST Group. Licensed under the MIT license.

from CybORG.Simulator.Actions.Action import Action
from CybORG.Shared.Logger import CybORGLogger


class RewardCalculator(CybORGLogger):
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.init_state = None
        self.init_obs = None
        self.previous_state = None
        self.previous_obs = None
        self.flat = False

        # Should this actually be a time.datetime?
        self.time = 0

    def calculate_simulation_reward(self, env_controller):
        current_state = env_controller._filter_obs(env_controller.get_true_state(env_controller.INFO_DICT['True'])).data
        action = env_controller.action
        agent_observations = env_controller.observation
        done = env_controller.done
        return self.calculate_reward(current_state, action, agent_observations, done)

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        raise NotImplementedError

    def tick(self):
        self.time += 1

    def reset(self):
        self.previous_state = self.init_state
        self.previous_obs = self.init_obs
        self.time = 0


class EmptyRewardCalculator(RewardCalculator):
    def calculate_reward(self, current_state: dict, action: Action, agent_observations: dict, done: bool):
        return 0.
