from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
import random

#agent that does random action

class TestAgent(BaseAgent):

    def __init__(self, test_action=None, epsilon=1.0):
        self.test_action = test_action
        self.epsilon = epsilon

    def train(self, results):
        pass

    def get_action(self, observation: dict, action_space: dict):
        if (random.random() < self.epsilon) or (self.test_action == None):
            action = []
            for a in action_space:
                if a > 0:
                    action.append(random.choice(range(a)))
                else:
                    action.append(0)
            return action
        else:
            return self.test_action

    def end_episode(self):
        pass

    def set_initial_values(self, action_space, observation):
        pass

