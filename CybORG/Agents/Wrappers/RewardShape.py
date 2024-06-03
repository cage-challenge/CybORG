import torch
from collections import deque
from CybORG.Shared import Results
from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper


class RewardShape(BaseWrapper):
    def __init__(self, env=None, agent=None):
        super().__init__(env, agent)
        self.action_buffer = deque(maxlen=2)
        self.observation_buffer = deque(maxlen=2)

    def step(self, agent=None, action=None) -> Results:
        result = self.env.step(agent, action)

        self.action_buffer.append(action)
        if torch.is_tensor(result.observation):
            self.observation_buffer.append(result.observation.tolist())
        else:
            self.observation_buffer.append(result.observation)

        if result.reward == 1.0:
            result.reward = 10.0
            result.done = True
            return result

        if len(self.action_buffer) == 2:
            if self.observation_buffer[0] == self.observation_buffer[1]:
                if self.action_buffer[0] == self.action_buffer[1]:
                    result.reward = -0.05
                else:
                    result.reward = -0.01
            else:
                result.reward = 0.01
                if action == 32 or action == 33 or action == 34:
                    result.reward = 1.0
        elif len(self.observation_buffer) == 2 and len(self.action_buffer) < 2:
            if self.observation_buffer[0] == self.observation_buffer[1]:
                result.reward = -0.01
            else:
                result.reward = 0.01
        else:
            pass

        return result

    def reset(self, agent=None, **kwargs):
        result = self.env.reset(agent, **kwargs)
        self.action_buffer = deque(maxlen=2)
        self.observation_buffer = deque(maxlen=2)
        if torch.is_tensor(result.observation):
            self.observation_buffer.append(result.observation.tolist())
        else:
            self.observation_buffer.append(result.observation)
        return result
