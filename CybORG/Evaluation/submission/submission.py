from CybORG.Agents.Wrappers import PettingZooParallelWrapper
from .RandomAgent import RandomAgent

agents = {f"blue_agent_{agent}": RandomAgent() for agent in range(18)}

def wrap(env):
    return PettingZooParallelWrapper(env=env)

submission_name = 'example'
submission_team = 'example_team'
submission_technique = 'Random Agents'
