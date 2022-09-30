# Copyright DST Group. Licensed under the MIT license.
import warnings
from typing import Any, Union

import gym
from gym.utils import seeding
from matplotlib import pyplot as plt

from CybORG.Shared import Observation, Results, CybORGLogger
from CybORG.Simulator.Actions import DiscoverNetworkServices, DiscoverRemoteSystems, ExploitRemoteService, \
    InvalidAction, \
    Sleep, PrivilegeEscalate, Impact, Remove, Restore, SeizeControl, RetakeControl, RemoveOtherSessions
from CybORG.Simulator.Actions.ConcreteActions.ActivateTrojan import ActivateTrojan
from CybORG.Simulator.Actions.ConcreteActions.ControlTraffic import BlockTraffic, AllowTraffic
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.ExploitAction import ExploitAction
from CybORG.Shared.Enums import DecoyType
from CybORG.Shared.EnvironmentController import EnvironmentController
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator
from CybORG.Shared.Scenarios.ScenarioGenerator import ScenarioGenerator
from CybORG.Tests.utils import CustomGenerator
# from CybORG.render.renderer import Renderer



class CybORG(CybORGLogger):
    """The main interface for the Cyber Operations Research Gym.

    The primary purpose of this class is to provide a unified interface for the CybORG simulation and emulation
    environments. The user chooses which of these modes to run when instantiating the class and CybORG initialises
    the appropriate environment controller.

    This class also provides the external facing API for reinforcement learning agents, before passing these commands
    to the environment controller. The API is intended to closely resemble that of OpenAI Gym.

    Attributes
    ----------
    scenario_generator : ScenarioGenerator
        ScenarioGenerator object that creates scenarios.
    environment : str, optional
        The environment to use. CybORG currently supports 'sim'
        and 'aws' modes (default='sim').
    env_config : dict, optional
        Configuration keyword arguments for environment controller
        (See relevant Controller class for details), (default=None).
    agents : dict, optional
        Defines the agent that selects the default action to be performed if the external agent does not pick an action
        If None agents will be loaded from description in scenario file (default=None).
    """
    supported_envs = ['sim', 'aws']

    def __init__(self,
                 scenario_generator: ScenarioGenerator,
                 environment: str = "sim",
                 env_config=None,
                 agents: dict = None,
                 seed: Union[int,CustomGenerator] = None):
        """Instantiates the CybORG class.

        Parameters
        ----------
        scenario_generator : ScenarioGenerator
            ScenarioGenerator object that creates scenarios.
        environment : str, optional
            The environment to use. CybORG currently supports 'sim'
            and 'aws' modes (default='sim').
        env_config : dict, optional
            Configuration keyword arguments for environment controller
            (See relevant Controller class for details), (default=None).
        agents : dict, optional
            Defines the agent that selects the default action to be performed if the external agent does not pick an action
            If None agents will be loaded from description in scenario file (default=None).
        """
        self.env = environment
        assert issubclass(type(scenario_generator), ScenarioGenerator), f'Scenario generator object of type {type(scenario_generator)} must be a subclass of ScenarioGenerator'
        self.scenario_generator = scenario_generator
        self._log_info(f"Using scenario generator {str(scenario_generator)}")
        if seed is None or type(seed) is int:
            self.np_random, seed = seeding.np_random(seed)
        else:
            self.np_random = seed
        self.environment_controller = self._create_env_controller(env_config, agents)
        # self.renderer:Renderer = None

    # getter method
    def get_renderer(self):
        return self.renderer

    def _create_env_controller(self, env_config, agents) -> EnvironmentController:
        """Chooses which Environment Controller to use then instantiates it.

        Parameters
        ----------
        """
        if self.env == 'sim':
            from CybORG.Simulator.SimulationController import SimulationController
            return SimulationController(self.scenario_generator, agents, self.np_random)
        raise NotImplementedError(
            f"Unsupported environment '{self.env}'. Currently supported "
            f"environments are: {self.supported_envs}"
        )

    def parallel_step(self, actions: dict = None, messages: dict = None, skip_valid_action_check: bool = False) -> (dict, dict, dict, dict):
        """Performs a step in CybORG for the given agent.

                Parameters
                ----------
                actions : dict
                    the actions to perform
                skip_valid_action_check : bool
                    a flag to diable the valid action check
                Returns
                -------
                tuple
                    the result of agent performing the action
                """
        if actions is self.environment_controller.action:
            warnings.warn("Reuse of the actions input. This variable is altered inside the simulation "
                          "and may contain actions from previous steps")
        self.environment_controller.step(actions, skip_valid_action_check)
        self.environment_controller.send_messages(messages)
        return {agent: obs.data for agent, obs in self.environment_controller.observation.items()}, \
               {agent: self.environment_controller.get_reward(agent) for agent
                in self.active_agents}, \
               {agent: self.environment_controller.done for agent in self.active_agents}, {}

    def step(self, agent: str = None, action=None, messages: dict = None, skip_valid_action_check: bool = False) -> Results:
        """Performs a step in CybORG for the given agent.
        Enables compatibility with older versions of CybORG including CAGE Challenge 1 and CAGE Challege 2

        Parameters
        ----------
        agent : str, optional
            the agent to perform step for (default=None)
        action : Action
            the action to perform
        skip_valid_action_check : bool
            a flag to diable the valid action check
        Returns
        -------
        Results
            the result of agent performing the action
        """
        if action is None or agent is None:
            action = {}
        else:
            action = {agent: action}
        self.environment_controller.step(action, skip_valid_action_check)
        self.environment_controller.send_messages(messages)
        if agent is None:
            result = Results(observation=Observation().data)
        else:
            result = Results(observation=self.get_observation(agent),
                             done=self.environment_controller.done,
                             reward=round(sum(self.environment_controller.get_reward(agent).values()), 1),
                             action_space=self.environment_controller.agent_interfaces[
                                 agent].action_space.get_action_space(),
                             action=self.environment_controller.action[agent])
        return result

    def start(self, steps: int, log_file=None, verbose=False) -> bool:
        """Start CybORG and run for a specified number of steps.

        Parameters
        ----------
        steps : int
            the number of steps to run for
        log_file : File, optional
            a file to write results to (default=None)

        Returns
        -------
        bool
            whether goal was reached or not
        """
        return self.environment_controller.start(steps, log_file, verbose)

    def get_true_state(self, info: dict) -> dict:
        """
        Query the current state.

        Parameters
        ----------
        info : dict
            Dictionary con

        Returns
        -------
        Results
            The information requested.
        """
        return self.environment_controller.get_true_state(info).data

    def get_agent_state(self, agent_name) -> dict:
        """
        Get the initial observation of the specified agent.

        Parameters
        ----------
        agent : str
            The agent to get the initial observation for.
            Set as 'True' to get the true-state.

        Returns
        -------
        dict
            The initial observation of the specified agent.
        """
        return self.environment_controller.get_agent_state(agent_name).data

    def reset(self, agent: str = None, seed: int = None) -> Results:
        """
        Resets CybORG and gets initial observation and action-space for the specified agent.

        Note
        ----
        This method is a critical part of the OpenAI Gym API.

        Parameters
        ----------
        agent : str, optional
            The agent to get the initial observation for.
            If None will return the initial true-state (default=None).

        Returns
        -------
        Results
            The initial observation and actions of an agent.
        """
        if seed is not None:
            self.np_random, seed = seeding.np_random(seed)
        return self.environment_controller.reset(agent=agent, np_random=self.np_random)

    def shutdown(self, **kwargs) -> bool:
        """
        Shuts down the CybORG environment.

        Parameters
        ----------
        **kwargs : dict, optional
            Keyword arguments to pass to the environment controller shutdown
            function. See the shutdown function of the specific environment
            controller used for details.

        Returns
        -------
        bool
            True if cyborg was shutdown without any issues.
        """
        self.environment_controller.shutdown(**kwargs)

    def pause(self):
        """Pauses the environment."""
        self.environment_controller.pause()

    def save(self, filepath: str):
        """
        Saves the CybORG environment to a file.

        Note
        ----
        Not currently supported for all environments.

        Parameters
        ----------
        filepath : str
            Path to file to save environment to.
        """
        self.environment_controller.save(filepath)

    def restore(self, filepath: str):
        """
        Restores the CybORG environment from a file.

        Note
        ----
        Not currently supported for all environments.

        Parameters
        ----------
        filepath : str
            Path to file to restore environment from.
        """
        self.environment_controller.restore(filepath)

    def get_observation(self, agent: str) -> dict:
        """
        Get the last observation for an agent.

        Parameters
        ----------
        agent : str
            Name of the agent to get observation for.

        Returns
        -------
        Observation
            The agent's last observation.
        """
        return self.environment_controller.get_last_observation(agent).data

    def get_action_space(self, agent: str):
        """
        Returns the most recent action space for the specified agent.

        Action spaces may change dynamically as the scenario progresses.

        Parameters
        ----------
        agent : str
            Name of the agent to get action space for.

        Returns
        -------
        dict
            The action space of the specified agent.

        """
        return self.environment_controller.get_action_space(agent)

    def get_observation_space(self, agent: str):
        """
        Returns the most recent observation for the specified agent.

        Parameters
        ----------
        agent : str
            Name of the agent to get observation space for.

        Returns
        -------
        dict
            The observation of the specified agent.

        """
        return self.environment_controller.get_observation_space(agent)

    def get_last_action(self, agent: str):
        """
        Returns the last executed action for the specified agent.

        Parameters
        ----------
        agent : str
            Name of the agent to get last action for.

        Returns
        -------
        Action
            The last action of the specified agent.

        """
        return self.environment_controller.get_last_action(agent)

    def set_seed(self, seed: int):
        """
        Sets a random seed.

        Parameters
        ----------
        seed : int
        """
        self.np_random, seed = seeding.np_random(seed)
        self.environment_controller.set_np_random(self.np_random)


    def get_ip_map(self):
        """
        Returns a mapping of hostnames to ip addresses for the current scenario.

        Returns
        -------
        dict
            The ip_map indexed by hostname.

        """
        return self.environment_controller.hostname_ip_map

    def get_cidr_map(self):
        return self.environment_controller.subnet_cidr_map

    def get_rewards(self):
        """
        Returns the rewards for each agent at the last executed step.

        Returns
        -------
        dict
            The rewards indexed by team name.

        """
        return self.environment_controller.reward

    def get_reward_breakdown(self, agent: str):
        # TODO: Docstring
        return self.environment_controller.get_reward_breakdown(agent)

    def get_attr(self, attribute: str) -> Any:
        """
        Returns the specified attribute if present.

        Intended to give wrappers access to the base CybORG class.

        Parameters
        ----------
        attribute : str
            Name of the requested attribute.

        Returns
        -------
        Any
            The requested attribute.
        """
        if hasattr(self, attribute):
            return self.__getattribute__(attribute)
        else:
            return None

    @property
    def agents(self) -> list:
        return [agent_name for agent_name, agent_info in self.environment_controller.agent_interfaces.items() if not agent_info.internal_only]
    #
    # def draw_link_diagram(self):
    #     """Draws the link diagram """
    #     if self.env == 'sim':
    #         G = self.environment_controller.state.link_diagram
    #         pos = nx.spring_layout(G, seed=self.np_random.get_state())  # Seed for reproducible layout
    #         nx.draw(G, pos)
    #         plt.show()

    @property
    def active_agents(self) -> list:
        return self.environment_controller.get_active_agents()

    def render(self, mode='human'):
        raise NotImplementedError("Rendering functionality is not currently available")
        assert self.env == 'sim', 'render is currently only available for the simulation'
        assert mode in ['human', 'rgb_array'], f"render is not available for {mode}, please use a mode from {['human', 'rgb_array']}"
        if self.renderer is None:
            self.renderer = Renderer()
        # Extract the data from the simulation.
        data = {'drones': {hostname: {"x": host_info.position[0],
                                      "y": host_info.position[1]} for hostname, host_info in
                           self.environment_controller.state.hosts.items()},
                'network': {hostname: [h for interface in host_info.interfaces for h in interface.data_links] for
                            hostname, host_info in
                            self.environment_controller.state.hosts.items()},
                'actions': [],
                "background": self.scenario_generator.background,
                'step': self.environment_controller.step_count}

        # get which hosts are red
        red_hosts = []
        red_low_hosts = []
        for agent in self.environment_controller.team['Red']:
            red_hosts += [i.hostname for i in self.environment_controller.state.sessions[agent].values() if
                          i.username == 'SYSTEM' or i.username == 'root']
            red_low_hosts += [i.hostname for i in self.environment_controller.state.sessions[agent].values()]
            # get agent actions
            if agent in self.environment_controller.action:
                red_action = self.environment_controller.action[agent]
                if type(red_action) in (Sleep, InvalidAction, ActivateTrojan):
                    continue
                red_from = agent
                if type(self.scenario_generator) is DroneSwarmScenarioGenerator:
                    red_source = 'drone_' + red_action.agent.split('_')[-1]
                else:
                    red_source = self.environment_controller.state.sessions[red_action.agent][red_action.session].hostname
                red_target = None
                if hasattr(red_action, 'subnet'):
                    red_target = [name for name, cidr in self.environment_controller.state.subnet_name_to_cidr.items() if
                                  cidr == red_action.subnet][0] + '_router'
                if hasattr(red_action, 'ip_address'):
                    red_target = self.environment_controller.state.ip_addresses[red_action.ip_address]
                if hasattr(red_action, 'hostname'):
                    red_target = red_action.hostname
                if red_target is not None:
                    if isinstance(red_action, DiscoverRemoteSystems):
                        red_action_type = 'network scan'
                    elif isinstance(red_action, (ExploitAction, ExploitRemoteService)):
                        red_action_type = 'exploit'
                    elif isinstance(red_action, (PrivilegeEscalate, SeizeControl)):
                        red_action_type = 'escalate'
                    elif isinstance(red_action, DiscoverNetworkServices):
                        red_action_type = 'port scan'
                    elif isinstance(red_action, Impact):
                        red_action_type = 'impact'
                    else:
                        red_action_type = type(red_action)
                    data['actions'].append(
                        {"agent": red_from, "destination": red_target, "source": red_source, "type": red_action_type})

        blue_hosts = []
        blue_protected_hosts = []
        for agent in self.environment_controller.team['Blue']:
            blue_hosts += [i.hostname for i in self.environment_controller.state.sessions[agent].values()]
            blue_protected_hosts += [blue_session.hostname for blue_session in
                                    self.environment_controller.state.sessions[agent].values() if
                                    len([host_proc for host_proc in
                                         self.environment_controller.state.hosts[blue_session.hostname].processes if
                                         host_proc.decoy_type != DecoyType.NONE]) > 0]
            if agent in self.environment_controller.action:
                blue_action = self.environment_controller.action[agent]
                if type(blue_action) in (Sleep, InvalidAction):
                    continue
                blue_from = blue_action.agent
                if type(self.scenario_generator) is DroneSwarmScenarioGenerator:
                    blue_source = 'drone_'+blue_action.agent.split('_')[-1]
                else:
                    blue_source = self.environment_controller.state.sessions[blue_action.agent][blue_action.session].hostname
                blue_target = None
                if hasattr(blue_action, 'subnet'):
                    blue_target = [name for name, cidr in self.environment_controller.state.subnet_name_to_cidr.items() if
                                   cidr == blue_action.subnet][0] + 'Subnet'
                elif hasattr(blue_action, 'ip_address'):
                    blue_target = self.environment_controller.state.ip_addresses[blue_action.ip_address]
                elif hasattr(blue_action, 'hostname'):
                    blue_target = blue_action.hostname
                elif hasattr(blue_action, 'session') and blue_action.session in self.environment_controller.state.sessions[blue_action.agent]:
                    blue_target = self.environment_controller.state.sessions[blue_action.agent][blue_action.session].hostname
                if blue_target is not None:
                    if type(blue_action) in (DiscoverNetworkServices, DiscoverRemoteSystems):
                        blue_action_type = 'scan'
                    elif type(blue_action) in (DiscoverNetworkServices, DiscoverRemoteSystems):
                        blue_action_type = 'exploit'
                    elif isinstance(blue_action, (Remove, RemoveOtherSessions)):
                        blue_action_type = "remove"
                    elif isinstance(blue_action, (Restore, RetakeControl)):
                        blue_action_type = "restore"
                    elif isinstance(blue_action, (AllowTraffic, BlockTraffic)):
                        blue_action_type = None
                    else:
                        blue_action_type = type(blue_action)
                    if blue_action_type is not None:
                        data['actions'].append(
                            {"agent": blue_from, "source": blue_source, "destination": blue_target, "type": blue_action_type})

        # 'BlueDrone', 'BlueDroneLowProvRed', 'RedDrone', 'BlueDroneProtected'


        for hostname, host_info in self.environment_controller.state.hosts.items():
            # if red high priv
            if hostname in red_hosts:
                data['drones'][hostname]['symbol'] = 'RedDrone'
            # if red low priv
            elif hostname in red_low_hosts:
                data['drones'][hostname]['symbol'] = 'BlueDroneLowPrivRed'
            # if blue protected
            elif hostname in blue_protected_hosts:
                data['drones'][hostname]['symbol'] = 'BlueDroneProtected'
            # else blue
            elif hostname in blue_hosts:
                data['drones'][hostname]['symbol'] = 'BlueDrone'
            # else neutral host
            else:
                data['drones'][hostname]['symbol'] = 'NeutralDrone'

        # add in rewards
        data['rewards'] = {}
        if 'Blue' not in self.environment_controller.reward:
            data['rewards']['Blue'] = 0
        else:
            data['rewards']['Blue'] = sum(self.environment_controller.reward['Blue'].values())
        data['rewards']['Red'] = - data['rewards']['Blue']
        # Step 2: process render data retrieved in previous step.
        self.renderer.process_render_data(data)
        # print(data['rewards'])
        # Step 3: render image.
        return self.renderer.render(mode=mode, verbose=False)

    def get_agent_ids(self):
        return list(self.environment_controller.agent_interfaces.keys())

    def close(self, **kwargs):
        self.environment_controller.shutdown(**kwargs)

    def get_message_space(self, agent: str) -> gym.Space:
        return self.environment_controller.get_message_space(agent)

    @property
    def unwrapped(self):
        return self
