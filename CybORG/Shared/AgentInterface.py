# Copyright DST Group. Licensed under the MIT license.

import sys

from CybORG.Shared import Scenario
from CybORG.Shared.ActionSpace import ActionSpace
from CybORG.Simulator.Actions.Action import Action
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
                 agent_obj,
                 agent_name,
                 actions,
                 allowed_subnets,
                 scenario,
                 active=True,
                 internal_only=False):
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
        self.last_action = None
        self.allowed_subnets = allowed_subnets
        self.scenario = scenario
        self.active = active
        self.internal_only = internal_only

        self.agent_name = agent_name
        self.action_space = ActionSpace(self.actions, agent_name, allowed_subnets)
        self.agent = agent_obj
        self.agent.set_initial_values(
            action_space=self.action_space.get_action_space(),
            observation=Observation().data
        )
        self.messages = []

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


    def get_action(self, observation: Observation, action_space: dict = None):
        """Gets an action from the agent to perform on the environment"""
        if isinstance(observation, Observation):
            observation = observation.data
        if action_space is None:
            action_space = self.action_space.get_action_space()
        self.last_action = self.agent.get_action(observation, action_space)
        return self.last_action

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
        self.action_space.reset(self.agent_name)
        self.agent.end_episode()

    def create_reward_calculator(self, reward_calculator: str, agent_name: str, scenario: Scenario) -> RewardCalculator:
        calc = None
        if reward_calculator == "Baseline":
            calc = BaselineRewardCalculator(agent_name)
        elif reward_calculator == 'PwnRewardCalculator':
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

    def get_observation_space(self):
        # returns the maximum observation space for the agent given its action set and the amount of parameters in the environment
        raise NotImplementedError
