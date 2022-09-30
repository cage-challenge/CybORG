# Copyright DST Group. Licensed under the MIT license.
import random
from typing import Any

from CybORG.Shared import Observation, Results, CybORGLogger
from CybORG.Shared.EnvironmentController import EnvironmentController

from CybORG.Simulator.SimulationController import SimulationController


class CybORG (CybORGLogger):
    """The main interface for the Cyber Operations Research Gym.

    The primary purpose of this class is to provide a unified interface for the CybORG simulation and emulation
    environments. The user chooses which of these modes to run when instantiating the class and CybORG initialises
    the appropriate environment controller.

    This class also provides the external facing API for reinforcement learning agents, before passing these commands
    to the environment controller. The API is intended to closely resemble that of OpenAI Gym.

    Attributes
    ----------
    scenario_file : str
        Path for valid scenario YAML file.
    environment : str, optional
        The environment to use. CybORG currently supports 'sim'
        and 'aws' modes (default='sim').
    env_config : dict, optional
        Configuration keyword arguments for environment controller
        (See relevant Controller class for details), (default=None).
    agents : dict, optional
        Map from agent name to agent interface for all agents to be used internally.
        If None agents will be loaded from description in scenario file (default=None).
    """
    supported_envs = ['sim', 'aws']

    def __init__(self,
                 scenario_file: str,
                 environment: str = "sim",
                 env_config=None,
                 agents: dict = None):
        """Instantiates the CybORG class.

        Parameters
        ----------
        scenario_file : str
            Path for valid scenario YAML file.
        environment : str, optional
            The environment to use. CybORG currently supports 'sim'
            and 'aws' modes (default='sim').
        env_config : dict, optional
            Configuration keyword arguments for environment controller
            (See relevant Controller class for details), (default=None).
        agents : dict, optional
            Map from agent name to agent interface for all agents to be used internally.
            If None agents will be loaded from description in scenario file (default=None).
        """
        self.env = environment
        self.scenario_file = scenario_file
        self._log_info(f"Using scenario file {scenario_file}")
        self.environment_controller = self._create_env_controller(
            env_config, agents
        )

    def _create_env_controller(self,
                               env_config,
                               agents) -> EnvironmentController:
        """Chooses which Environment Controller to use then instantiates it.

        Parameters
        ----------
        """
        if self.env == 'sim':
            return SimulationController(self.scenario_file, agents=agents)
        if self.env == 'aws':

            if env_config:
                return AWSClientController(
                    self.scenario_file, agents=agents, **env_config
                )
            else:
                return AWSClientController(self.scenario_file, agents=agents)
        raise NotImplementedError(
            f"Unsupported environment '{self.env}'. Currently supported "
            f"environments are: {self.supported_envs}"
        )

    def step(self, agent: str = None, action=None, skip_valid_action_check: bool = False) -> Results:
        """Performs a step in CybORG for the given agent.

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
        return self.environment_controller.step(agent, action, skip_valid_action_check)

    def start(self, steps: int, log_file=None) -> bool:
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
        return self.environment_controller.start(steps, log_file)

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

    def reset(self, agent: str = None) -> Results:
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
        return self.environment_controller.reset(agent=agent)

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
        random.seed(seed)

    def get_ip_map(self):
        """
        Returns a mapping of hostnames to ip addresses for the current scenario.

        Returns
        -------
        dict
            The ip_map indexed by hostname.

        """
        return self.environment_controller.hostname_ip_map
    
    def get_rewards(self):
        """
        Returns the rewards for each agent at the last executed step.

        Returns
        -------
        dict
            The rewards indexed by agent name.

        """
        return self.environment_controller.reward

    def get_reward_breakdown(self,agent:str):
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
