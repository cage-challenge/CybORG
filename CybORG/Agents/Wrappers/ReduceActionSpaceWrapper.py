import inspect
from typing import Union

from CybORG import CybORG
from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper
from CybORG.Shared import Results


class ReduceActionSpaceWrapper(BaseWrapper):
    def __init__(self, env: Union[BaseWrapper, CybORG]=None, agent=None):
        super().__init__(env, agent)
        self.action_signature = {}
        self.known_params = {}
        self.params_to_fix_at_start = ['port']
        self.fixed_size = {}

    def action_space_change(self, action_space: dict) -> dict:
        assert type(action_space) is dict, f"Wrapper required a dictionary action space. " \
                                           f"Please check that the wrappers below the ReduceActionSpaceWrapper return the action space as a dict"

        for param in self.params_to_fix_at_start:
            if param in self.fixed_size:
                remove_keys = []
                for p in action_space[param].keys():
                    if p not in self.fixed_size[param]:
                        remove_keys.append(p)

                for key in remove_keys:
                    action_space[param].pop(key)
                # action_space[param] = self.fixed_size[param]
            else:
                self.fixed_size[param] = list(action_space[param].keys())
        params = ['action']
        for action in action_space['action']:
            if action not in self.action_signature:
                self.action_signature[action] = inspect.signature(action).parameters
            for p in self.action_signature[action]:
                if p not in params:
                    params.append(p)
        to_remove = []
        for key, value in action_space.items():
            if key not in params:
                to_remove.append(key)

        for p in to_remove:
            action_space.pop(p)

        return action_space

    def get_attr(self,attribute:str):
        return self.env.get_attr(attribute)

    def reset(self, agent=None):
        self.fixed_size = {}
        return self.env.reset(agent)
