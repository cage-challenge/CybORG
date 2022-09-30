import inspect

from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper
from CybORG.Shared import Results


# this wrapper converts a list into an action object based on the action space
from CybORG.Simulator.Actions import Sleep


class IntListToActionWrapper(BaseWrapper):
    def __init__(self, env=None, agent=None):
        super().__init__(env)
        self.action_space = None
        self.action_params = None
        self.param_name = None
        self.selection_mask = None

        self.action_signature = {}
        self.known_params = {}
        self.params_to_fix_at_start = ['port']
        self.fixed_size = {}


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

    def reset(self, agent=None, seed=None):
        result = self.env.reset(agent, seed)
        result.action_space, result.selection_masks = self.action_space_change(result.action_space)
        self.selection_mask = result.selection_masks
        result.observation = self.observation_change(agent, result.observation)
        return result

    def get_action_space(self, agent: str) -> dict:
        action_space, selection_mask = self.action_space_change(self.env.get_action_space(agent))
        self.selection_mask = selection_mask
        return action_space

    def action_space_change(self, action_space: dict) -> (list, list):
        self.action_space = action_space
        # first remove old parameters
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
