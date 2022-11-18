## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.

import gym


from CybORG.Shared import Scenario, CybORGLogger
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.Action import InvalidAction, Sleep
from CybORG.Shared.AgentInterface import AgentInterface
from CybORG.Shared.Observation import Observation
from CybORG.Shared.Results import Results
from CybORG.Shared.RewardCalculator import RewardCalculator
from CybORG.Shared.Scenarios.ScenarioGenerator import ScenarioGenerator


class EnvironmentController(CybORGLogger):
    """The Abstract base controller for CybORG environment controllers

    Provides the abstract methods which all CybORG controllers must implement. This includes setup and teardown,
    modifying the state, and pulling out data from the environment.
    When both Simulation and Emulation share common functionality, it is implemented here.


    Attributes
    ----------
    scenario_dict : dict
        the scenario data
    agent_interfaces : dict[str: AgentInterface]
        agent interface object for agents in scenario
    """

    def __init__(self, scenario_generator: ScenarioGenerator, agents, np_random):
        """Instantiates the Environment Controller.
        Parameters
        ----------
        scenario_generator : ScenarioGenerator
            An object that generates scenarios for the environment
        agents : dict, optional
            map from agent name to agent interface of agents to be used in
            environment. If None agents will be loaded from description in
            scenario file (default=None)
        """
        self.end_turn_actions = {}
        self.hostname_ip_map = None
        self.subnet_cidr_map = None
        self.scenario_generator = scenario_generator
        self.np_random = np_random
        scenario = scenario_generator.create_scenario(np_random)
        self._create_environment(scenario)
        self.max_bandwidth = scenario.max_bandwidth
        self.step_count = 0
        self.agents = agents
        self.agent_interfaces = self._create_agents(scenario, agents)
        self.team_reward_calculators = scenario.get_reward_calculators()
        self.team = scenario.team_agents
        self.team_assignments = scenario.get_team_assignments()
        self.reward = {}
        self.INFO_DICT = {}
        self.action = {}
        self.observation = {}
        self.INFO_DICT['True'] = {}
        for host in scenario.hosts:
            self.INFO_DICT['True'][host] = {'System info': 'All', 'Sessions': 'All', 'Interfaces': 'All', 'User info': 'All',
                                      'Processes': ['All']}
        self.init_state = self._filter_obs(self.get_true_state(self.INFO_DICT['True'])).data
        for agent in scenario.agents:
            self.INFO_DICT[agent] = scenario.get_agent_info(agent).osint.get('Hosts', {})
            for host in self.INFO_DICT[agent].keys():
                self.INFO_DICT[agent][host]['Sessions'] = agent
        # populate initial observations with OSINT
        for agent_name, agent in self.agent_interfaces.items():
            self.observation[agent_name] = self._filter_obs(self.get_true_state(self.INFO_DICT[agent_name]), agent_name)
            agent.set_init_obs(self.observation[agent_name].data, self.init_state)
        self.message_length = 16
        self.done = self.determine_done()
        # calculate reward for each team
        for team_name, team_calcs in self.team_reward_calculators.items():
            self.reward[team_name] = {}
            for reward_name, r_calc in team_calcs.items():
                self.reward[team_name][reward_name] = self.calculate_reward(r_calc)
        self._log_debug(f"Finished init()")

    def reset(self, agent: str = None, np_random=None) -> Results:
        """Resets the environment and get initial agent observation and actions.

        Parameters
        ----------
        agent : str, optional
            the agent to get initial observation for, if None will return
            initial white state (default=None)

        Returns
        -------
        Results
            The initial observation and actions of a agent or white team
        """
        self.reward = {}
        self.action = {}
        self.observation = {}
        self.step_count = 0
        if np_random is not None:
            self.np_random = np_random
        scenario = self.scenario_generator.create_scenario(self.np_random)
        self._create_environment(scenario)

        self.agent_interfaces = self._create_agents(scenario, self.agents)
        self.team = scenario.team_agents
        self.team_assignment = {agent_name: team_name for team_name, agent_names in scenario.team_agents.items() for agent_name in agent_names}
        self.max_bandwidth = scenario.max_bandwidth
        self.init_state = self._filter_obs(self.get_true_state(self.INFO_DICT['True'])).data
        for agent_name, agent_object in self.agent_interfaces.items():
            self.observation[agent_name] = self._filter_obs(self.get_true_state(self.INFO_DICT[agent_name]), agent_name)
            agent_object.set_init_obs(self.observation[agent_name].data, self.init_state)
        self.done = self.determine_done()
        # calculate reward for each team
        for team_name, team_calcs in self.team_reward_calculators.items():
            self.reward[team_name] = {}
            for reward_name, r_calc in team_calcs.items():
                self.reward[team_name][reward_name] = self.calculate_reward(r_calc)
        if agent is None:
            return Results(observation=self.init_state)
        else:
            return Results(observation=self.observation[agent].data,
                           action_space=self.agent_interfaces[agent].action_space.get_action_space())

    def step(self, actions: dict = None, skip_valid_action_check=False):

        """Updates the environment based on the joint actions of all agents
        Save the

        Parameters
        ----------
        actions : dict{str: Action}/
            name of the agent and the action they perform
        skip_valid_action_check: bool=False/
            if false then action is checked against the agents action space to determine validity of action and .
            if not valid then the action is replaced with an InvalidAction object
        Returns
        -------
        None
        """
        self.step_count += 1
        if actions is None:
            actions = {}
        # fill in missing actions based on default agents and check validity of actions
        for agent_name, agent_object in self.agent_interfaces.items():
            agent_object.messages = []
            if agent_name not in actions:
                actions[agent_name] = agent_object.get_action(self.get_last_observation(agent_name))
            if not skip_valid_action_check:
                actions[agent_name] = self.replace_action_if_invalid(actions[agent_name], agent_object)

        self.action = actions
        actions = self.sort_action_order(actions)

        # clear old observations
        self.observation = {}

        # execute actions in order of priority
        for agent_name, agent_action in actions.items():
            self.observation[agent_name] = self._filter_obs(self.execute_action(agent_action), agent_name)

        # execute additional default end turn actions
        for agent_name, agent_action in self.end_turn_actions.items():
            if self.is_active(agent_name):
                self.observation[agent_name] = self._filter_obs(self.execute_action(agent_action[0](**agent_action[1])), agent_name).combine_obs(self.get_last_observation(agent_name))

        for agent_name, observation in self.observation.items():
            if self.scenario_generator.update_each_step or len(self.get_action_space(agent_name)['session']) == 0:
                self.agent_interfaces[agent_name].update(observation)

        # calculate done signal
        self.done = self.scenario_generator.determine_done(self)

        # reset previous reward
        self.reward = {}

        # calculate reward for each team
        for team_name, team_calcs in self.team_reward_calculators.items():
            self.reward[team_name] = {}
            for reward_name, r_calc in team_calcs.items():
                self.reward[team_name][reward_name] = self.calculate_reward(r_calc)
            self.reward[team_name]['action_cost'] = sum([actions.get(agent, Action()).cost for agent in self.team[team_name]])

    def send_messages(self, messages: dict = None):
        """Sends messages between agents"""
        if messages is None:
            messages = {}

        for agent, message in messages.items():
            assert self.get_message_space(agent).contains(message), f'{agent} attempting to send message {message} that is not in the message space {self.get_message_space(agent)}'
            for other_agent in self.get_connected_agents(agent):
                self.agent_interfaces[other_agent].messages.append(message)

        for agent, observation in self.observation.items():
            if len(self.agent_interfaces[agent].messages) > 0:
                observation.data['message'] = self.agent_interfaces[agent].messages

    def get_connected_agents(self, agent: str) -> list:
        """Gets a list of agents that are connected the the agent"""
        raise NotImplementedError

    def get_message_space(self, agent) -> gym.Space:
        msg_space = gym.spaces.MultiBinary(self.message_length)
        msg_space._np_random = self.np_random
        return msg_space

    def sort_action_order(self, actions: dict) -> dict:
        """Reorders the actions to determine order of execution"""
        return {agent_name: agent_action for agent_name, agent_action in actions.items() if type(agent_action) not in [Sleep, InvalidAction]}

    def set_np_random(self, np_random):
        self.np_random = np_random

    def execute_action(self, action: Action) -> Observation:
        """Execute an action in the environment"""
        raise NotImplementedError

    def determine_done(self) -> bool:
        """The done signal is always false
        Returns
        -------
        bool
            whether goal was reached or not
        """
        return self.scenario_generator.determine_done(self)

    def calculate_reward(self, reward_calculator: RewardCalculator) -> float:
        """Calculates the reward using the reward calculator
        Arguments
        -------
        RewardCalculator
            An object to calculate the reward
        Returns
        -------
        float
            The reward value for the associated reward calculator
        """
        raise NotImplementedError

    def start(self, steps: int = None, log_file=None, verbose=False):
        """Start the environment and run for a specified number of steps.

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
        done = False
        max_steps = 0
        if steps is None:
            while not done:
                if verbose:
                    print(max_steps)
                max_steps += 1
                self.step()
            if verbose:
                print('Red Wins!')  # Junk Test Code
        else:
            for step in range(steps):
                max_steps += 1
                self.step()
                if verbose:
                    print(max_steps)
                done = self.done
                if step == 500:
                    print(step)  # Junk Test Code
                if done:
                    print(f'Red Wins at step {step}')  # Junk Test Code
                    break

            # print(f"{agent_name}'s Reward: {self.reward[agent_name]}")
        if log_file is not None:
            log_file.write(
                f"{max_steps},{self.reward['Red']},{self.reward['Blue']},"
                f"{self.agent_interfaces['Red'].agent.epsilon},"
                f"{self.agent_interfaces['Red'].agent.gamma}\n"
            )
        return done

    def get_true_state(self, info: dict) -> Observation:
        """Get current True state

        Returns
        -------
        Observation
            current true state
        """
        raise NotImplementedError

    def get_agent_state(self, agent_name: str) -> Observation:
        return self.get_true_state(self.INFO_DICT[agent_name])

    def get_last_observation(self, agent: str) -> Observation:
        """Get the last observation for an agent

        Parameters
        ----------
        agent : str
            name of agent to get observation for

        Returns
        -------
        Observation
            agents last observation
        """
        return self.observation[agent] if agent in self.observation else Observation()

    def get_action_space(self, agent: str) -> dict:
        """
        Gets the action space for a chosen agent
        agent: str
            agent selected
        """
        if agent in self.agent_interfaces:
            return self.agent_interfaces[agent].action_space.get_action_space()
        raise ValueError(f'Agent {agent} not in agent list {self.agent_interfaces.keys()}')

    def get_observation_space(self, agent: str) -> dict:
        """
                Gets the observation space for a chosen agent
                agent: str
                    agent selected
                """
        if agent in self.agent_interfaces:
            return self.agent_interfaces[agent].get_observation_space()
        raise ValueError(f'Agent {agent} not in agent list {self.agent_interfaces.values()}')

    def get_last_action(self, agent: str) -> Action:
        """
                Gets the observation space for a chosen agent
                agent: str
                    agent selected
                """
        return self.action[agent] if agent in self.action else None

    def restore(self, filepath: str):
        """Restores the environment from file

        Parameters
        ----------
        filepath : str
            path to file to restore env from
        """
        raise NotImplementedError

    def save(self, filepath: str):
        """Saves the environment to file

        Parameters
        ----------
        filepath : str
            path to file to save env to
        """
        raise NotImplementedError

    def pause(self):
        """Pauses the environment"""
        pass

    def shutdown(self, teardown: bool = True) -> bool:
        """Shutdown environment, deleting/terminating resources
        as required

        Parameters
        ----------
        teardown : bool, optional
            if True environment resources will be terminated if applicable,
            otherwise resources will not be terminated (allowing them to be
            reused if desired) (default=True)

        Returns
        -------
        bool
            True if the environment was shutdown without issue
        """
        raise NotImplementedError

    def _create_agents(self, scenario, agent_classes: dict = None) -> dict:
        agents = {}

        for agent_name in scenario.agents:
            agent_info = scenario.get_agent_info(agent_name)
            if agent_classes is not None and agent_name in agent_classes:
                agent_obj = agent_classes[agent_name]
            else:
                agent_obj = agent_info.agent_type
            agent_obj.np_random = self.np_random
            agent_obj.end_episode()
            agents[agent_name] = AgentInterface(
                agent_obj,
                agent_name,
                agent_info.actions,
                allowed_subnets=agent_info.allowed_subnets,
                scenario=scenario,
                active = agent_info.active,
                internal_only = agent_info.internal_only
            )
        return agents

    def _create_environment(self, scenario: Scenario):
        raise NotImplementedError

    def _filter_obs(self, obs: Observation, agent_name=None):
        """Filter obs to contain only hosts/subnets in scenario network """
        if self.scenario_generator.update_each_step:
            if agent_name is not None:
                subnets = [self.subnet_cidr_map[s] for s in self.agent_interfaces[agent_name].allowed_subnets]
            else:
                subnets = list(self.subnet_cidr_map.values())

            obs.filter_addresses(
                ips=self.hostname_ip_map.values(),
                cidrs=subnets,
                include_localhost=False
            )
        return obs

    def replace_action_if_invalid(self, action: Action, agent: AgentInterface):
        # returns action if the parameters in the action are in and true in the action set else return InvalidAction imbued with bug report.
        action_space = agent.action_space.get_action_space()

        if type(action) not in action_space['action']:
            message = f'Action {action} not in action space for agent {agent.agent_name}.'
            return InvalidAction(action=action, error=message)

        if not action_space['action'][type(action)]:
            message = f'Action {action} is not valid for agent {agent.agent_name} at the moment. This usually means it is trying to access a host it has not discovered yet.'
            return InvalidAction(action=action, error=message)

        # next for each parameter in the action
        for parameter_name, parameter_value in action.get_params().items():
            if parameter_name not in action_space:
                continue

            if parameter_value not in action_space[parameter_name]:
                message = f'Action {action} has parameter {parameter_name} valued at {parameter_value}. However, {parameter_value} is not in the action space for agent {agent.agent_name}.'
                return InvalidAction(action=action, error=message)

            if not action_space[parameter_name][parameter_value]:
                message = f'Action {action} has parameter {parameter_name} valued at the invalid value of {parameter_value}. This usually means an agent is trying to utilise information it has not discovered yet such as an ip_address or port number.'
                return InvalidAction(action=action, error=message)

        return action

    def get_reward_breakdown(self, agent:str):
        return self.agent_interfaces[agent].reward_calculator.host_scores

    def get_active_agents(self) -> list:
        """returns a list of agent names which have active server sessions
        Excludes agents that are marked as internal only"""
        raise NotImplementedError

    def is_active(self, agent_name: str) -> bool:
        """tests if agent has an active server session"""
        raise NotImplementedError

    def get_reward(self, agent):
        team = [team_name for team_name, agents in self.team_assignments.items() if agent in agents][0]
        return self.reward[team]

