# Copyright DST Group. Licensed under the MIT license.


from CybORG.Shared import Scenario
from CybORG.Simulator.Actions.Action import Action, RemoteAction
from CybORG.Shared.EnvironmentController import EnvironmentController
from CybORG.Shared.Observation import Observation
from CybORG.Shared.RewardCalculator import RewardCalculator
from CybORG.Shared.Scenarios.ScenarioGenerator import ScenarioGenerator
from CybORG.Simulator.State import State


class SimulationController(EnvironmentController):
    """The class that controls the Simulation environment.

    Inherits from Environment Controller then implements simulation-specific functionality.
    Most methods are either disabled or delegate their functionality to the State attribute.
    The main thing this class currently does is parse the scenario file.
    """
    def __init__(self, scenario_generator: ScenarioGenerator, agents, np_random):
        self.state = None
        self.bandwidth_usage = {}
        self.dropped_actions = []
        self.routeless_actions = []
        self.blocked_actions = []
        super().__init__(scenario_generator, agents, np_random)

    def reset(self, agent=None, np_random=None):
        return super(SimulationController, self).reset(agent, np_random)

    def step(self, actions: dict = None, skip_valid_action_check=False):
        """Updates the simulation environment based on the joint actions of all agents
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
        super(SimulationController, self).step(actions, skip_valid_action_check)
        for host in self.state.hosts.values():
            host.update(self.state)
        self.state.update_data_links()

    def pause(self):
        pass

    def set_np_random(self, np_random):
        super(SimulationController, self).set_np_random(np_random)
        self.state.set_np_random(np_random)

    def execute_action(self, action: Action) -> Observation:
        return action.execute(self.state)

    def restore(self, file: str):
        pass

    def save(self, file: str):
        pass

    def get_true_state(self, info: dict) -> Observation:
        output = self.state.get_true_state(info)
        return output

    def shutdown(self, **kwargs):
        pass

    def _create_environment(self, scenario: Scenario):
        self.state = State(scenario, self.np_random)
        self.hostname_ip_map = {h: ip for ip, h in self.state.ip_addresses.items()}
        self.subnet_cidr_map = self.state.subnet_name_to_cidr
        self.end_turn_actions = scenario.get_end_turn_actions()

    def run_schtasks(self):
        for host in self.hosts:
            host.run_scheduled_tasks(self.step)


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
        return reward_calculator.calculate_simulation_reward(self)

    def get_active_agents(self) -> list:
        """returns a dict of agent names as the key and a list of active sessions as the values"""
        return [agent_name for agent_name, sessions in self.state.sessions.items() if len([session.ident for session in sessions.values() if session.active and session.parent is None]) > 0 and not self.agent_interfaces[agent_name].internal_only]

    def is_active(self, agent_name: str) -> bool:
        """tests if agent has an active server session"""
        return len([session.ident for session in self.state.sessions[agent_name].values() if session.active and session.parent is None]) > 0

    def sort_action_order(self, actions: dict) -> dict:
        """Sorts the actions based on priority and sets the dropped parameter for actions based on bandwidth usage"""
        actions = super(SimulationController, self).sort_action_order(actions)
        # check agent and session exist for each action
        actions = {agent_name: agent_action for agent_name, agent_action in actions.items() if not hasattr(agent_action, 'session') or (agent_action.agent in self.state.sessions and agent_action.session in self.state.sessions[agent_action.agent])}

        # shuffle action order to randomise which are dropped if bandwidth exceeded
        agent_send_order = list(actions.keys())
        self.np_random.shuffle(agent_send_order)

        # use bandwidth until exceeded then drop actions
        bandwidth_usage = {}
        self.routeless_actions = []
        self.blocked_actions = []
        self.dropped_actions = []

        for agent in agent_send_order:
            a = actions[agent]
            if issubclass(type(a), RemoteAction):
                route = a.get_used_route(self.state)
                if route is not None:
                    for host in route:
                        # if blocked then action consumes no further bandwidth
                        if host in self.state.blocks and route[0] in self.state.blocks[host]:
                            a.blocked = host
                            self.blocked_actions.append(a)
                            break
                        # otherwise action consumes bandwidth at host
                        if host in bandwidth_usage:
                            bandwidth_usage[host] += a.bandwidth_usage
                        else:
                            bandwidth_usage[host] = a.bandwidth_usage
                        # and bandwidth from all surrounding hosts
                        for interface in self.state.hosts[host].interfaces:
                            if interface.interface_type == 'wireless':
                                for h in interface.data_links:
                                    if h in bandwidth_usage:
                                        bandwidth_usage[h] += a.bandwidth_usage
                                    else:
                                        bandwidth_usage[h] = a.bandwidth_usage
                        # if the maximum bandwidth is exceeded then the action is droppped and doesn't continue down the route
                        if bandwidth_usage[host] > self.max_bandwidth:
                            self.dropped_actions.append(a)
                            a.dropped = True
                            break
                else:
                    a.dropped = True
                    self.routeless_actions.append(a)
        self.bandwidth_usage = dict(bandwidth_usage)

        # sort the actions based on priority
        actions = {agent_name: agent_action for agent_name, agent_action in sorted(actions.items(), key=lambda item: item[1].priority)}

        return actions

    def get_connected_agents(self, agent: str) -> list:
        """Gets a list of agents that are connected the the agent"""
        # get agents host
        hostname = None
        for sessions, session_obj in self.state.sessions[agent].items():
            if session_obj.parent == None:
                hostname = session_obj.hostname

        if hostname is None:
            return [agent]

        # get all connected hosts
        connected_hosts = []
        for host in self.state.hosts.keys():
            if RemoteAction.check_routable(self.state, host, hostname):
                connected_hosts.append(host)

        # get agents on connected hosts
        connected_agents = []
        for agent, sessions in self.state.sessions.items():
            for session in sessions.values():
                if session.hostname in connected_hosts and session.parent is None:
                    connected_agents.append(agent)
                    break
        return connected_agents