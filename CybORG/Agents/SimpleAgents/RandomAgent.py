from inspect import signature
from typing import Union

from gym import Space
from gym.vector.utils import spaces

from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent

#agent that does random action
from CybORG.Simulator.Actions import Sleep


class RandomAgent(BaseAgent):
    """Takes a random action or a test action based on the epsilon value"""

    def __init__(self, name=None, test_action=None, epsilon=1.0, np_random = None):
        super().__init__(name, np_random)
        self.test_action = test_action
        self.epsilon = epsilon
        self.action_params = None

    def train(self, results):
        pass

    def get_action(self, observation: dict, action_space: Union[Space, dict]):
        if (self.np_random.random() < self.epsilon) or (self.test_action is None):
            # select random action
            if isinstance(action_space, Space):
                return action_space.sample()
            elif type(action_space) is dict:
                invalid_actions = []
                while True:
                    options = [i for i, v in action_space['action'].items() if v and i not in invalid_actions]
                    if len(options) > 0:
                        action_class = self.np_random.choice(options)
                    else:
                        return Sleep()
                    # select random options
                    action_params = {}
                    for param_name in self.action_params[action_class]:
                        options = [i for i, v in action_space[param_name].items() if v]
                        if len(options) > 0:
                            action_params[param_name] = self.np_random.choice(options)
                        else:
                            invalid_actions.append(action_class)
                            action_params = None
                            break
                    if action_params is not None:
                        return action_class(**action_params)
            else:
                raise ValueError("Random agent can only handle Space or dict action space")
        else:
            return self.test_action

    def end_episode(self):
        pass

    def set_initial_values(self, action_space, observation):
        if type(action_space) is dict:
            self.action_params = {action_class: signature(action_class).parameters for action_class in action_space['action'].keys()}
