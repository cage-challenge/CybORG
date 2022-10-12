from typing import Optional

from CybORG import CybORG
from CybORG.Agents.Wrappers import BaseWrapper
import warnings
from gym import spaces
import numpy as np

from pettingzoo import ParallelEnv
from pettingzoo.utils import wrappers
from CybORG.Agents.Wrappers import BaseWrapper, OpenAIGymWrapper, BlueTableWrapper, RedTableWrapper, EnumActionWrapper
from CybORG.Shared.CommsRewardCalculator import CommsAvailabilityRewardCalculator


class PettingZooParallelWrapper(BaseWrapper):
    def __init__(self, env: CybORG):
        super().__init__(env)
        self._agent_ids = self.possible_agents
        # assuming that the final value in the agent name indicates which drone that agent is on
        self.agent_host_map = {agent_name: f'drone_{agent_name.split("_")[-1]}' for agent_name in self.possible_agents}
        # get all ip_addresses
        self.ip_addresses = list(self.unwrapped.get_ip_map().values())
        num_drones = len(self.ip_addresses)
        self._action_spaces = {agent: spaces.Discrete(len(self.get_action_space(agent))) for agent in
                               self.possible_agents}
        # success + own_drone(block Ips + processes + network conns + pos) + other_drones(IPs + session_+pos)
        self._observation_spaces = {agent_name: spaces.MultiDiscrete(
            [3] + [2 for i in range(num_drones)] + [2] + [3 for i in range(num_drones)] + [101, 101] + (
                    num_drones - 1) * [num_drones, 101, 101, 2]) for agent_name in self.possible_agents}
        self.metadata = {"render_modes": ["human", "rgb_array"], "name": "Cage_Challenge_3"}
        self.seed = 117

        self.dones = {agent: False for agent in self.possible_agents}
        self.rewards = {agent: 0. for agent in self.possible_agents}
        self.infos = {}

    def reset(self,
              seed: Optional[int] = None,
              return_info: bool = False,
              options: Optional[dict] = None) -> dict:
        res = self.env.reset()
        self.dones = {agent: False for agent in self.possible_agents}
        self.rewards = {agent: 0. for agent in self.possible_agents}
        self.infos = {}
        # assuming that the final value in the agent name indicates which drone that agent is on
        self.agent_host_map = {agent_name: f'drone_{agent_name.split("_")[-1]}' for agent_name in self.possible_agents}
        self.ip_addresses = list(self.env.get_ip_map().values())
        return {agent: self.observation_change(agent, obs=self.env.get_observation(agent)) for agent in self.agents}

    def step(self, actions: dict) -> (dict, dict, dict, dict):
        actions, msgs = self.select_messages(actions)
        for agent, act in actions.items():
            assert self.action_space(agent).contains(act)

        raw_obs, rews, dones, infos = self.env.parallel_step(actions, messages=msgs)
        # green_agents = {agent: if }
        # rews = GreenAvailabilityRewardCalculator(raw_obs, ['green_agent_0','green_agent_1', 'green_agent_2' ]).calculate_reward()
        obs = {agent: self.observation_change(agent, raw_obs[agent]) for agent in self.env.active_agents}
        # obs = {agent: self.observation_change(agent, obs) for agent in self.possible_agents}
        # set done to true if maximumum steps are reached
        self.dones.update(dones)
        self.rewards = {agent: float(sum(rews[agent].values())) for agent in self.env.active_agents}
        # send messages
        return obs, self.rewards, dones, infos

    def parse_message(self, message: list, agent_name: str):
        return []

    def select_messages(self, action):
        return action, {}

    def render(self, mode="human"):
        # Insert code from phillip
        return self.env.render(mode)

    def close(self):
        # Insert code from phillip
        return self.env.close()

    @property
    def observation_spaces(self):
        '''
        Returns the observation space for every possible agent
        '''
        try:
            return {agent: self.observation_space(agent) for agent in self.possible_agents}
        except AttributeError:
            raise AttributeError(
                "The base environment does not have an `observation_spaces` dict attribute. Use the environments `observation_space` method instead"
            )

    @property
    def action_spaces(self):
        '''
        Returns the action space for every possible agent
        '''
        try:
            return {agent: self.action_space(agent) for agent in self.possible_agents}
        except AttributeError:
            raise AttributeError(
                "The base environment does not have an action_spaces dict attribute. Use the environments `action_space` method instead"
            )

    def get_rewards(self):
        '''
        Returns the rewards for every possible agent
        '''
        try:
            return {agent: self.get_reward(agent) for agent in self.possible_agents}
        except AttributeError:
            raise AttributeError(
                "The base environment does not have an action_spaces dict attribute. Use the environments `action_space` method instead"
            )

    def get_dones(self):
        '''
        Returns the dones for every possible agent
        '''
        try:
            return {agent: self.get_done(agent) for agent in self.possible_agents}
        except AttributeError:
            raise AttributeError(
                "The base environment does not have an action_spaces dict attribute. Use the environments `action_space` method instead"
            )

    def observation_space(self, agent: str):
        '''
        Returns the observation space for a single agent

        Parameters:
            agent -> str
        '''
        return self._observation_spaces[agent]

    def action_space(self, agent: str):
        '''
        Returns the action space for a single agent

        Parameters:
            agent -> str
        '''
        return self._action_spaces[agent]

    def get_reward(self, agent):
        '''
        Returns the reward for a single agent

        Parameters:
            agent -> str
        '''
        return self.rewards[agent]

    def get_done(self, agent):
        '''
        Returns the dones for a single agent

        Parameters:
            agent -> str
        '''
        return self.dones[agent]

    def get_action_space(self, agent):
        '''
        Obtains the action_space of the specified agent

        Parameters:
            agent -> str
        '''
        this_agent = agent
        initial = self.env.get_action_space(agent)

        unmasked_as = []
        agent_actions = []
        action_list = ['ExploitDroneVulnerability', 'SeizeControl', 'FloodBandwidth', 'BlockTraffic', 'AllowTraffic',
                       'RetakeControl', 'SendData']

        for key in initial.copy():
            if key != 'action':
                del initial[key]

        init_list = list(initial['action'].items())
        for i in range(len(init_list)):
            agent_actions.append(init_list[i][0].__name__)

        if ('Sleep' in agent_actions):
            unmasked_as.append('Sleep')

        if ('RemoveOtherSessions' in agent_actions):
            unmasked_as.append(f'Remove {this_agent}')

        for act in action_list:
            if (act in agent_actions):
                for agent in self.possible_agents:
                    unmasked_as.append(f"{act} {agent}")

        return unmasked_as

    def observation_change(self, agent: str, obs: dict):
        '''Initialises the observation space for the agent (if undefined) or modifies the observation space (if defined)

        Parameters:
            agent -> str

        OG_obs -> None/np.array
            None if undefined
            np.array if defined
        '''
        # assuming that the final value in the agent name indicates which drone that agent is on
        if 'agent' in agent:
            self.agent_host_map = {agent_name: f'drone_{agent_name.split("_")[-1]}' for agent_name in self.possible_agents}
            # get all ip_addresses
            self.ip_addresses = list(self.env.get_ip_map().values())
            num_drones = len(self.ip_addresses)
            obs_length = int(1 + num_drones + 1 + num_drones + 2 + (num_drones - 1) * (2 + 1 + 1))
            new_obs = np.zeros(obs_length, dtype=np.int)
            if obs is not None:
                own_host_name = self.agent_host_map[agent]
                # obs_length = success + own_drone(block Ips + processes + network conns) + other_drones_including_own(IPs + session_ + pos)
                # element location --> [0, 1,...,num_drones, 1+num_drones, 2+num_drones, ..., 2+2*num_drones, 3+2*num_drones, 4+2*num_drones,...,4+4*num_drones]
                index = 0
                # success
                new_obs[index] = obs['success'].value
                index += 1

                if agent in self.env.active_agents:
                    # Add blocked IPs
                    for i, ip in enumerate(self.ip_addresses):
                        new_obs[index + i] = 1 if ip in [interface['blocked_ips'] for interface in
                                                         obs[own_host_name]['Interface'] if
                                                         'blocked_ips' in interface] else 0
                    index += len(self.ip_addresses)

                    # add flagged malicious processes
                    new_obs[index] = 1 if 'Processes' in obs[own_host_name] else 0
                    index += 1
                    # add flagged messages
                    for i, ip in enumerate(self.ip_addresses):
                        # TODO add in check for network connections
                        new_obs[i] = 1 if ip in [interface['Network Connections'] for interface in
                                                 obs[own_host_name]['Interface'] if
                                                 'Network Connections' in interface] else 0
                    index += len(self.ip_addresses)

                    pos = obs[own_host_name]['System info'].get('position', (0, 0))
                    new_obs[index] = max(int(pos[0]), 0)
                    new_obs[index + 1] = max(int(pos[1]), 0)
                    index += 2
                    ip_host_map = {ip: host for host, ip in self.env.get_ip_map().items()}
                    # add information of other drones
                    for i, ip in enumerate(self.ip_addresses):
                        hostname = ip_host_map[ip]
                        if hostname != own_host_name:
                            new_obs[index] = i
                            index += 1
                            # add position of drone
                            if hostname in obs:
                                pos = obs[hostname]['System info'].get('position', (0, 0))
                                new_obs[index] = max(int(pos[0]), 0)
                                new_obs[index + 1] = max(int(pos[1]), 0)
                                index += 2
                                # add session to drone
                                new_obs[index] = 1 if 'Session' in obs[hostname] else 0
                                index += 1
                            else:
                                new_obs[index] = 0
                                new_obs[index + 1] = 0
                                new_obs[index + 2] = 0
                                index += 3

                    msg = self.parse_message(obs['message'] if 'message' in obs else [], agent)
                    if len(msg) > 0:
                        new_obs = np.concatenate((new_obs, np.array(msg)))
                # update data of other drones
                # try:
                assert self._observation_spaces[agent].contains(
                    new_obs), f'Observation \n{new_obs}\n is not contained within Observation Space \n{self._observation_spaces[agent]}\n for agent {agent}'
                # except AssertionError:
                #     breakpoint()
            return new_obs

    def get_attr(self, attribute: str):
        return self.env.get_attr(attribute)

    def get_last_actions(self, agent):
        return self.get_attr('get_last_action')(agent)

    @property
    def agents(self):
        return [agent for agent in self.env.active_agents if not self.dones[agent]]

    @property
    def possible_agents(self):
        return self.env.agents
