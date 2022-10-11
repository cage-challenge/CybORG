import numpy as np
from gym import spaces, Env
from typing import Union, List, Optional

from CybORG import CybORG
from prettytable import PrettyTable

from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper


class OpenAIGymWrapper(Env, BaseWrapper):
    def __init__(self, env: BaseWrapper, agent_name: str):
        super().__init__(env)
        self.agent_name = agent_name
        if isinstance(self.get_action_space(self.agent_name), list):
            self.action_space = spaces.MultiDiscrete(self.get_action_space(self.agent_name))
        else:
            assert isinstance(self.get_action_space(self.agent_name), dict)
            self.action_space = spaces.Discrete(len(self.get_action_space(self.agent_name)))
        box_len = len(self.observation_change(agent_name, self.env.reset(self.agent_name).observation))
        self.observation_space = spaces.Box(-1.0, 3.0, shape=(box_len,), dtype=np.float32)
        self.reward_range = (float('-inf'), float('inf'))
        self.metadata = {}
        self.action = None

    def step(self, action: Union[int, List[int]] = None) -> (object, float, bool, dict):
        self.action = action
        result = self.env.step(self.agent_name, action)
        result.observation = self.observation_change(self.agent_name, result.observation)
        result.action_space = self.action_space_change(result.action_space)
        info = vars(result)
        return np.array(result.observation), result.reward, result.done, info

    @property
    def np_random(self):
        return self.env.get_attr('np_random')

    def reset(self, *, seed: Optional[int] = None, return_info: bool = False, options: Optional[dict] = None):
        result = self.env.reset(self.agent_name, seed)
        result.action_space = self.action_space_change(result.action_space)
        result.observation = self.observation_change(self.agent_name, result.observation)
        if return_info:
            return np.array(result.observation, dtype=np.float32), {}
        else:
            return np.array(result.observation, dtype=np.float32)

    def render(self, mode):
        # TODO: If FixedFlatWrapper it will error out!
        if mode == 'human':
            self.env.render(mode)
        else:
            if self.agent_name == 'Red':
                table = PrettyTable({
                    'Subnet',
                    'IP Address',
                    'Hostname',
                    'Scanned',
                    'Access',
                })
                for ip in self.get_attr('red_info'):
                    table.add_row(self.get_attr('red_info')[ip])
                table.sortby = 'IP Address'
                if self.action is not None:
                    _action = self.get_attr('possible_actions')[self.action]
                    return print(f'\nRed Action: {_action}\n{table}')
            elif self.agent_name == 'Blue':
                table = PrettyTable({
                    'Subnet',
                    'IP Address',
                    'Hostname',
                    'Activity',
                    'Compromised',
                })
                for hostid in self.get_attr('info'):
                    table.add_row(self.get_attr('info')[hostid])
                table.sortby = 'Hostname'
                if self.action is not None:
                    _action = self.get_attr('possible_actions')[self.action]
                    red_action = self.get_last_action(agent=self.agent_name)
                    return print(f'\nBlue Action: {_action}\nRed Action: {red_action}\n{table}')
            return print(table)

    def get_attr(self,attribute:str):
        return self.env.get_attr(attribute)

    def get_observation(self, agent: str):
        observation = self.env.get_observation(agent)
        observation = self.observation_change(self.agent_name, observation)
        return np.array(observation, dtype=np.float32)

    def get_agent_state(self,agent:str):
        return self.get_attr('get_agent_state')(agent)

    def get_action_space(self,agent):
        return self.env.get_action_space(agent)

    def get_last_action(self,agent):
        return self.get_attr('get_last_action')(agent)

    def get_ip_map(self):
        return self.get_attr('get_ip_map')()

    def get_rewards(self):
        return self.get_attr('get_rewards')()
