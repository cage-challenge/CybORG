from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
from CybORG.Shared import Results
from CybORG.Simulator.Actions import Sleep, Monitor

class ConstantAgent(BaseAgent):

    def __init__(self, action, name=None):
        super().__init__(name)
        self.action = action

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        pass

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        return self.action

    def end_episode(self):
        """Allows an agent to update its internal state"""
        pass

    def set_initial_values(self, action_space, observation):
        pass

class SleepAgent(ConstantAgent):
    def __init__(self, name=None, **kwargs):
        action = Sleep()
        super().__init__(action, name)

class MonitorAgent(ConstantAgent):
    def __init__(self):
        action = Monitor(agent='Blue', session=0)
        super().__init__(action)

