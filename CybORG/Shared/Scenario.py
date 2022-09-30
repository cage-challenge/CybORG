# Copyright DST Group. Licensed under the MIT license.
import itertools
import sys
from typing import List

import numpy as np

from CybORG.Agents import BaseAgent, SleepAgent
from CybORG.Shared.BaselineRewardCalculator import BaselineRewardCalculator
from CybORG.Shared.BlueRewardCalculator import HybridAvailabilityConfidentialityRewardCalculator
from CybORG.Shared.RedRewardCalculator import HybridImpactPwnRewardCalculator, DistruptRewardCalculator, \
    PwnRewardCalculator
from CybORG.Shared.RewardCalculator import EmptyRewardCalculator

from CybORG.Shared import CybORGLogger


class ScenarioSession(CybORGLogger):
    """A dataclass for handling scenario information of a session """

    def __init__(self, name: str, username: str, session_type, hostname: str, parent=None, num_children: int = 0,
                 event_artifacts: list = None):
        """
        Parameters
        ----------
        username: str
            the name of the user that is running the session
        session_type
        hostname: str
            the name of the host running the session
        parent
        num_children: int
            the number of child sessions this session is the parent of
        event_artifacts: list
        name: str
            the name of the session
        """
        self.username = username
        self.session_type = session_type
        self.hostname = hostname
        self.parent = parent
        self.num_children = num_children
        if event_artifacts is None:
            self.event_artifacts = []
        else:
            self.event_artifacts = event_artifacts
        self.name = name

    @classmethod
    def load(cls, session_info: dict):
        return cls(username=session_info.get("username"),
                   session_type=session_info.get("type"),
                   hostname=session_info.get("hostname"),
                   parent=session_info.get("parent", None),
                   num_children=session_info.get("num_children_sessions", 0),
                   event_artifacts=session_info.get("artifacts", []),
                   name=session_info.get('name', None))

    def __str__(self):
        return f"ScenarioSession {self.name}, {self.parent} -> {self.username}@{self.hostname}: {self.session_type}"


class ScenarioAgent(CybORGLogger):
    """A dataclass for handling scenario information of an agent

    Is essentially a wrapper around the definition for a single agent
    in the scenario dictionary, and provides a consistent interface to
    agent data without having to remember string keys, etc.
    """

    def __init__(self,
                 agent_name: str,
                 team: str,
                 starting_sessions: list,
                 actions: list,
                 osint: dict,
                 allowed_subnets: list,
                 agent_type: BaseAgent = None,
                 active: bool = True,
                 default_actions: tuple = None,
                 internal_only: bool = False):
        """
        Parameters
        ----------
        agent_name: str
            Name of the agent
        team : str
            the name of the team the agent is a part of
        starting_sessions: list
            the list of sessions the agent starts with
        actions: list
            the list of actions an agent may perform
        osint: dict
            the information the agent begins a game with
        agent_type: BaseAgent
            the class that selects the default actions of the agent
        active: bool
            determines if the agent starts active or inactive at the start of the game
        default_actions : tuple
            the action_class, action_kwargs for actions being performed at the end of a turn by this agent
        internal_only : bool
            marks if an agent is restricted from using the external cyborg interfaces,
            useful if you want to enforce a default behaviour for that agent
        """
        self.name = agent_name
        self.team = team
        self.starting_sessions = []
        for session in starting_sessions:
            self.starting_sessions.append(session)
        self.actions = actions
        if agent_type is not None:
            self.agent_type = agent_type
        else:
            self.agent_type = SleepAgent()
        self.osint = osint
        self.allowed_subnets = allowed_subnets
        self.active = active
        self.default_actions = default_actions
        self.internal_only = internal_only

    @staticmethod
    def get_action_classes(actions):
        action_classes = []
        action_module = sys.modules['CybORG.Simulator.Actions']
        for action in actions:
            action_classes.append(getattr(action_module, action))
        return action_classes

    @classmethod
    def load(cls, agent_name: str, agent_info: dict):
        return cls(agent_name=agent_name,
                   team=agent_info.get('team'),
                   actions=cls.get_action_classes(agent_info.get("actions", [])),
                   starting_sessions=[ScenarioSession.load(i) for i in agent_info.get("starting_sessions", [])],
                   agent_type=getattr(sys.modules['CybORG.Agents'], agent_info.get("agent_type", SleepAgent))(),
                   allowed_subnets=agent_info.get("AllowedSubnets", []),
                   osint=agent_info.get("INT", {}))


class ScenarioHost:
    def __init__(self, hostname, processes=None, host_type='host', system_info=None, user_info=None, interface_info=None, services=None, image=None, info=None, aws_info=None,
                 confidentiality_value: str = None, availability_value: str = None, respond_to_ping: bool = True, starting_position=np.array([0.0, 0.0])):
        self.hostname = hostname
        self.host_type = host_type
        self.aws_info = aws_info
        self.image = image
        self.processes = processes
        self.starting_position = starting_position
        self.system_info = system_info
        self.user_info = user_info
        if interface_info is None:
            self.interface_info = []
        else:
            self.interface_info = interface_info
        self.services = services
        self.info = info
        self.confidentiality_value = confidentiality_value
        self.availability_value = availability_value
        self.respond_to_ping = respond_to_ping

    @classmethod
    def load(cls, hostname: str, host_info: dict):
        return cls(hostname=hostname,
                   aws_info=host_info.get("AWS_Info", []),
                   image=host_info.get("image"),
                   processes=host_info.get("Processes"),
                   system_info=host_info.get("System info"),
                   user_info=host_info.get("User Info"),
                   info=host_info.get("info", {}),
                   services=host_info.get("Services"),
                   confidentiality_value=host_info.get("ConfidentialityValue", None),
                   availability_value=host_info.get("AvailabilityValue", None))

    def get_availability_value(self, default):
        return self.availability_value if self.availability_value is not None else default

    def get_confidentiality_value(self, default):
        return self.confidentiality_value if self.confidentiality_value is not None else default


class ScenarioSubnet:
    def __init__(self, subnet_name, size, hosts, nacls=None, cidr=None, ip_addresses=None):
        self.subnet_name = subnet_name
        self.size = size
        self.hosts = hosts
        self.nacls = nacls if nacls is not None else {}
        self.cidr = cidr
        self.ip_addresses = ip_addresses

    @classmethod
    def load(cls, subnet_name, subnet_info):
        return cls(subnet_name=subnet_name,
                   size=subnet_info.get('Size'),
                   hosts=subnet_info.get('Hosts'),
                   nacls=subnet_info.get('NACLs'))

    def __str__(self):
        output = f"ScenarioAgent: name={self.name} _info={self._info} \nsessions=\n"

        for session in self.starting_sessions:
            output += f"{session}"

        return output

class Scenario(CybORGLogger):
    """A dataclass that contains the initial state information"""

    def __init__(self, agents: dict = None, team_calcs: dict = None, team_agents: dict = None, hosts: dict = None, subnets: dict = None,
                 predeployed: bool = False, max_bandwidth: int = 1000):
        if agents is None:
            self.agents = {}
        else:
            self.agents = agents

        agent_starting_sessions = [agent.starting_sessions for agent in self.agents.values()]
        self.starting_sessions = list(itertools.chain(agent_starting_sessions))

        if team_calcs is None:
            self.team_calc = {}
        else:
            self.team_calc = {agent_name: self._get_reward_calcs(agent_name, calc_names) for agent_name, calc_names in
                          team_calcs.items()}
        if team_agents is None:
            self.team_agents = {}
        else:
            self.team_agents = team_agents

        if hosts is None:
            self.hosts = {}
        else:
            self.hosts = hosts

        if subnets is None:
            self.subnets = {}
        else:
            self.subnets = subnets

        self.predeployed = predeployed
        self.max_bandwidth = max_bandwidth

        self.operational_firewall = False

    def _get_reward_calcs(self, agent_name, reward_calc_names):
        return {name: self._get_reward_calculator(agent_name, name, adversary) for name, adversary \
                in reward_calc_names}

    def _get_reward_calculator(self, team_name, reward_calculator, adversary):
        if reward_calculator == "Baseline":
            calc = BaselineRewardCalculator(team_name)
        elif reward_calculator == 'Pwn':
            calc = PwnRewardCalculator(team_name, self)
        elif reward_calculator == 'Disrupt':
            calc = DistruptRewardCalculator(team_name, self)
        elif reward_calculator == 'None' or reward_calculator is None:
            calc = EmptyRewardCalculator(team_name)
        elif reward_calculator == 'HybridAvailabilityConfidentiality':
            calc = HybridAvailabilityConfidentialityRewardCalculator(team_name, self, adversary)
        elif reward_calculator == 'HybridImpactPwn':
            calc = HybridImpactPwnRewardCalculator(team_name, self)
        else:
            raise ValueError(f"Invalid calculator selection: {reward_calculator} for team {team_name}")

        return calc

    @classmethod
    def load(cls, scenario_dict: dict):
        return cls(agents={name: ScenarioAgent.load(name, info) for name, info in scenario_dict['Agents'].items()},
                   team_calcs=scenario_dict['team_calcs'],
                   team_agents=scenario_dict['team_agents'],
                   hosts={hostname: ScenarioHost.load(hostname=hostname, host_info=host_info) for hostname, host_info in
                          scenario_dict['Hosts'].items()},
                   subnets={subnet_name: ScenarioSubnet.load(subnet_name=subnet_name, subnet_info=subnet_info) for
                            subnet_name, subnet_info in scenario_dict['Subnets'].items()},

                   predeployed=scenario_dict.get("predeployed", False))

    def get_subnet_size(self, subnetname: str) -> int:
        return self.subnets[subnetname].size

    def get_subnet_hosts(self, subnetname: str) -> List[str]:
        return self.subnets[subnetname].hosts

    def get_subnet_nacls(self, subnetname: str) -> dict:
        subnet_info = self.subnets[subnetname]
        return subnet_info.nacls

    def get_host_image_name(self, hostname: str) -> str:
        return self.hosts[hostname]["image"]

    def get_host(self, hostname: str) -> ScenarioHost:
        return self.hosts[hostname]

    def get_team_info(self, team_name: str) -> dict:
        return {'calcs': self.team_calc[team_name], 'agents': self.team_agents[team_name]}

    def get_host_subnet_names(self, hostname: str) -> List[str]:
        return [s for s in self.subnets if hostname in self.get_subnet_hosts(s)]

    def get_agent_info(self, agent_name: str) -> ScenarioAgent:
        return self.agents[agent_name]

    def get_reward_calculators(self) -> dict:
        return {team_name: reward_calculators for team_name, reward_calculators \
                in self.team_calc.items()}

    def get_teams(self) -> list:
        return list(self.team_calc.keys())

    def get_end_turn_actions(self) -> dict:
        """Returns the end turn action that is performed by an agent"""
        return {agent_name: data.default_actions for agent_name, data in self.agents.items() if data.default_actions is not None}

    def get_team_assignments(self) -> dict:
        return self.team_agents

    def __str__(self):
        return pprint.pformat(self._scenario, depth=7)