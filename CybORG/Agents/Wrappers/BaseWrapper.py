from typing import Union, Any

from CybORG import CybORG
from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
from CybORG.Shared import Results


class BaseWrapper:
    def __init__(self, env: CybORG = None):
        # wrapper allows changes to be made to the interface between external agents via specification of the env
        self.env = env

    def step(self, agent=None, action=None) -> Results:
        result = self.env.step(agent, action)
        result.observation = self.observation_change(agent, result.observation)
        result.action_space = self.action_space_change(result.action_space)
        return result

    def reset(self, agent=None, seed = None):
        result = self.env.reset(agent, seed)
        result.action_space = self.action_space_change(result.action_space)
        result.observation = self.observation_change(agent, result.observation)
        return result

    def observation_change(self, agent: str, observation: dict):
        return observation

    def action_space_change(self, action_space: dict) -> dict:
        return action_space

    def get_action_space(self, agent: str) -> dict:
        return self.action_space_change(self.env.get_action_space(agent))

    def get_observation(self, agent: str):
        return self.observation_change(agent, self.env.get_observation(agent))

    def get_last_action(self, agent: str):
        return self.env.get_last_action(agent=agent)

    def set_seed(self, seed: int):
        self.env.set_seed(seed)

    @property
    def active_agents(self) -> list:
        return self.env.active_agents

    def shutdown(self, **kwargs) -> bool:
        """Shutdown CybORG

        Parameters
        ----------
        **kwargs : dict, optional
            keyword arguments to pass to environment controller shutdown
            function. See the shutdown function of the specific environment
            controller used for details.

        Returns
        -------
        bool
            True if cyborg was shutdown without issue
        """
        return self.env.shutdown(**kwargs)

    def get_attr(self, attribute: str) -> Any:
        """gets a specified attribute from this wrapper if present of requests it from the wrapped environment

                Parameters
                ----------
                attribute : str
                    name of the requested attribute

                Returns
                -------
                Any
                    the requested attribute
                """
        if hasattr(self, attribute):
            return self.__getattribute__(attribute)
        else:
            return self.env.get_attr(attribute)

    def render(self, mode):
        return self.env.render(mode)

    @property
    def agents(self):
        return self.env.agents

    @property
    def unwrapped(self):
        return self.env.unwrapped
