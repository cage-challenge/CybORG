import inspect

from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper
from CybORG.Shared import Results


# this wrapper converts a list into an action object based on the action space
from CybORG.Shared.Actions import Sleep


class IntListToActionWrapper(BaseWrapper):
    def __init__(self, env=None, agent=None):
        super().__init__(env, agent)
        self.action_space = None
        self.action_params = None
        self.param_name = None
        self.selection_mask = None

    def step(self, agent=None, action: list = None) -> Results:
        if action is not None:
            try:
                action_obj = self.get_action(agent, action)
            except:
                print('Error')
        else:
            action_obj = None
        result = self.env.step(agent, action_obj)
        result.action_space, result.selection_masks = self.action_space_change(result.action_space)
        self.selection_mask = result.selection_masks
        result.action_name = str(action_obj)
        return result

    def reset(self, agent=None, **kwargs):
        result = self.env.reset(agent, **kwargs)
        result.action_space, result.selection_masks = self.action_space_change(result.action_space)
        self.selection_mask = result.selection_masks
        result.observation = self.observation_change(result.observation)
        return result

    def get_action_space(self, agent: str) -> dict:
        action_space, selection_mask = self.action_space_change(self.env.get_action_space(agent))
        self.selection_mask = selection_mask
        return action_space

    def action_space_change(self, action_space: dict) -> (list, list):
        self.action_space = action_space
        selection_masks = []
        new_action_space = []
        self.param_name = []
        for key, value in action_space.items():
            if len(value) > 1:
                new_action_space.append(len(value))
                selection_masks.append([list(value.keys()).index(i) for i, v in value.items() if v])
                self.param_name.append(key)
        return new_action_space, selection_masks

    def get_action(self, agent: str, action: list):
        """converts a list to an action object"""
        opts = {}
        if self.action_space is None:
            self.get_action_space(agent)
        action_class = list(self.action_space['action'])[action[0]]
        if self.action_params is None:
            self.action_params = {}
            for ac in self.action_space['action'].keys():
                self.action_params[ac] = inspect.signature(ac).parameters
        count = 0
        for key, value in self.action_space.items():
            if key in self.action_params[action_class]:
                if len(value) > 1:
                    if action[count] < len(value):
                        if list(value.values())[action[count]]:
                            opts[key] = list(value.keys())[action[count]]
                else:
                    if list(value.values())[0]:
                        opts[key] = list(value.keys())[0]
            if len(value) > 1:
                count += 1
        try:
            action_obj = action_class(**opts)
        except TypeError:
            action_obj = Sleep()
        return action_obj

    def get_attr(self,attribute:str):
        return self.env.get_attr(attribute)
