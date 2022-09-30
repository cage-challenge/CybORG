from CybORG.Shared import Results

class BaseAgent:

    def train(self, results: Results):
        """allows an agent to learn a policy"""
        raise NotImplementedError

    def get_action(self, observation, action_space):
        """gets an action from the agent that should be performed based on the agent's internal state and provided observation and action space"""
        raise NotImplementedError

    def end_episode(self):
        """Allows an agent to update its internal state"""
        raise NotImplementedError

    def set_initial_values(self, action_space, observation):
        raise NotImplementedError
