# Copyright DST Group. Licensed under the MIT license.

import sys

from CybORG.Shared import Scenario
from CybORG.Shared.ActionSpace import ActionSpace
from CybORG.Shared.Actions.Action import Action
from CybORG.Shared.BaselineRewardCalculator import BaselineRewardCalculator
from CybORG.Shared.BlueRewardCalculator import HybridAvailabilityConfidentialityRewardCalculator
from CybORG.Shared.Observation import Observation
from CybORG.Shared.RedRewardCalculator import DistruptRewardCalculator, PwnRewardCalculator, \
    HybridImpactPwnRewardCalculator
from CybORG.Shared.Results import Results
from CybORG.Shared.RewardCalculator import RewardCalculator, EmptyRewardCalculator

MAX_HOSTS = 5
MAX_PROCESSES = 100    # 50
MAX_CONNECTIONS = 10
MAX_VULNERABILITIES = 1
MAX_INTERFACES = 4
MAX_FILES = 10
MAX_SESSIONS = 10    # 80
MAX_USERS = 10
MAX_GROUPS = 10
MAX_PATCHES = 10


class AgentInterface:

    def __init__(self,
                 agent_class,
                 agent_name,
                 actions,
                 reward_calculator_type,
                 allowed_subnets,
                 scenario,
                 wrappers=None):
        self.hostname = {}
        self.username = {}
        self.group_name = {}
        self.process_name = {}
        self.interface_name = {}
        self.path = {}
        self.password = {}
        self.password_hash = {}
        self.file = {}
        self.actions = actions
        self.reward_calculator_type = reward_calculator_type
        self.last_action = None
        self.scenario = scenario
        self.reward_calculator = self.create_reward_calculator(
            self.reward_calculator_type, agent_name, scenario
        )
        self.agent_name = agent_name
        self.action_space = ActionSpace(self.actions, agent_name, allowed_subnets)
        self.agent = agent_class()
        if wrappers is not None:
            for wrapper in wrappers:
                if wrapper != 'None':
                    self.agent = getattr(sys.modules['CybORG.Agents.Wrappers'], wrapper)(agent=self.agent)
        self.agent.set_initial_values(
            action_space=self.action_space.get_max_action_space(),
            observation=Observation().data
        )

    def update(self, obs: dict, known=True):
        if isinstance(obs, Observation):
            obs = obs.data
        self.action_space.update(obs, known)

    def set_init_obs(self, init_obs, true_obs):
        if isinstance(init_obs, Observation):
            init_obs = init_obs.data
        if isinstance(true_obs, Observation):
            true_obs = true_obs.data
        self.update(true_obs, False)
        self.update(init_obs, True)
        self.reward_calculator.previous_state = true_obs
        self.reward_calculator.init_state = true_obs

        self.reward_calculator.previous_obs = init_obs
        self.reward_calculator.init_obs = init_obs

    def get_action(self, observation: Observation, action_space: dict = None):
        """Gets an action from the agent to perform on the environment"""
        if isinstance(observation, Observation):
            observation = observation.data
        if action_space is None:
            action_space = self.action_space.get_action_space()
        self.last_action = self.agent.get_action(observation, action_space)
        return self.last_action

    def train(self, result: Results):
        """Trains an agent with the new tuple from the environment"""
        if isinstance(result.observation, Observation):
            result.observation = result.observation.data
        if isinstance(result.next_observation, Observation):
            result.next_observation = result.next_observation.data
        result.action = self.last_action
        self.agent.train(result)

    def end_episode(self):
        self.agent.end_episode()
        self.reset()

    def reset(self):
        self.hostname = {}
        self.username = {}
        self.group_name = {}
        self.process_name = {}
        self.interface_name = {}
        self.path = {}
        self.password = {}
        self.password_hash = {}
        self.file = {}
        self.reward_calculator.reset()
        self.action_space.reset(self.agent_name)
        self.agent.end_episode()

    def create_reward_calculator(self, reward_calculator: str, agent_name: str, scenario: Scenario) -> RewardCalculator:
        calc = None
        if reward_calculator == "Baseline":
            calc = BaselineRewardCalculator(agent_name)
        elif reward_calculator == 'Pwn':
            calc = PwnRewardCalculator(agent_name, scenario)
        elif reward_calculator == 'Disrupt':
            calc = DistruptRewardCalculator(agent_name, scenario)
        elif reward_calculator == 'None' or reward_calculator is None:
            calc = EmptyRewardCalculator(agent_name)
        elif reward_calculator == 'HybridAvailabilityConfidentiality':
            calc = HybridAvailabilityConfidentialityRewardCalculator(agent_name, scenario)
        elif reward_calculator == 'HybridImpactPwn':
            calc = HybridImpactPwnRewardCalculator(agent_name, scenario)
        else:
            raise ValueError(f"Invalid calculator selection: {reward_calculator} for agent {agent_name}")
        return calc

    def determine_reward(self, agent_obs: dict, true_obs: dict, action: Action, done: bool) -> float:
        return self.reward_calculator.calculate_reward(current_state=true_obs, action=action,
                                                       agent_observations=agent_obs, done=done)

    def get_observation_space(self):
        # returns the maximum observation space for the agent given its action set and the amount of parameters in the environment
        raise NotImplementedError
