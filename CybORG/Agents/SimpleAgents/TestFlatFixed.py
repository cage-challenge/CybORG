from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
import random


class TestFlatFixedAgent(BaseAgent):

    def __init__(self, action_size=None, state_size=None, test_action=None, epsilon=1.0):
        self.test_action = test_action
        self.epsilon = epsilon
        self.len_obs = None

    def train(self, results):
        assert type(results.observation) is list
        for element in results.observation:
            assert type(element) is float
        if self.len_obs is None:
            self.len_obs = len(results.observation)
        assert self.len_obs == len(results.observation)

    def get_action(self, observation, action_space):
        assert type(action_space) is int
        assert type(observation) is list
        for element in observation:
            assert type(element) is float
        if self.len_obs is None:
            self.len_obs = len(observation)
        assert self.len_obs == len(observation)
        return random.choice(range(action_space))  # Assuming action_space is a list

    def end_episode(self):
        pass
