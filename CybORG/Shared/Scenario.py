# Copyright DST Group. Licensed under the MIT license.
import yaml
import pprint
from typing import Union, List


class ScenarioSession:
    """A dataclass for handling scenario information of a session """

    def __init__(self, session_info: dict):
        """
        Parameters
        ----------
        session_info : dict
            Scenario definition of session
        """
        self._info = session_info

    @property
    def username(self) -> str:
        return self._info["username"]

    @property
    def session_type(self) -> str:
        return self._info["type"]

    @property
    def hostname(self) -> str:
        return self._info["hostname"]

    @property
    def parent(self) -> int:
        return self._info.get("parent", None)

    @property
    def num_children(self) -> int:
        return self._info.get("num_children_sessions", 0)

    @property
    def event_artifacts(self) -> List[str]:
        return self._info.get("artifacts", [])

    @property
    def name(self) -> str:
        return self._info.get("name", None)

    def __str__(self):
        return f"Session {self.name}, {self.parent} -> {self.username}@{self.hostname}: {self.session_type}"


class ScenarioAgent:
    """A dataclass for handling scenario information of an agent

    Is essentially a wrapper around the definition for a single agent
    in the scenario dictionary, and provides a consistent interface to
    agent data without having to remember string keys, etc.
    """

    def __init__(self, agent_name: str, agent_info: dict):
        """
        Parameters
        ----------
        agent_name: str
            Name of the agent
        agent_info : dict
            Scenario definition of the agent
        """
        self.name = agent_name
        self._info = agent_info
        self.starting_sessions = []
        for session_info in agent_info.get("starting_sessions", []):
            session = ScenarioSession(session_info)
            self.starting_sessions.append(session)

    @property
    def agent_type(self) -> str:
        return self._info.get("agent_type", None)

    @property
    def wrappers(self) -> List[str]:
        return self._info.get("wrappers", [])

    @property
    def actions(self) -> List[str]:
        return self._info.get("actions", [])

    @property
    def reward_calculator_type(self) -> str:
        return self._info.get("reward_calculator_type", None)

    @property
    def osint(self) -> dict:
        return self._info.get("INT", {})

    @property
    def allowed_subnets(self) -> List[str]:
        return self._info.get("AllowedSubnets", [])

    @property
    def adversary(self) -> str:
        return self._info.get('adversary')


class Scenario:
    """A dataclass for handling scenario information.

    Is essentially a wrapper around the scenario dictionary, that provides
    a consistent interface to scenario data.
    """

    def __init__(self, scenario_dict: dict):
        self._scenario = scenario_dict
        self._agents = {}
        for name, info in self._scenario["Agents"].items():
            self._agents[name] = ScenarioAgent(name, info)

    @classmethod
    def load(cls, scenario_file_path: str):
        with open(scenario_file_path) as fIn:
            scenario_dict = yaml.load(fIn, Loader=yaml.FullLoader)
        return cls(scenario_dict)

    @property
    def subnets(self) -> List[str]:
        return list(self._scenario["Subnets"])

    @property
    def hosts(self) -> List[str]:
        return list(self._scenario["Hosts"])

    @property
    def agents(self) -> List[str]:
        return list(self._agents)

    @property
    def starting_sessions(self) -> List[ScenarioSession]:
        sessions = []
        for agent in self._agents.values():
            for s in agent.starting_sessions:
                sessions.append(s)
        return sessions

    @property
    def predeployed(self) -> bool:
        return self._scenario.get("predeployed", False)

    def get_subnet_size(self, subnetname: str) -> int:
        return self._scenario["Subnets"][subnetname]["Size"]

    def get_subnet_hosts(self, subnetname: str) -> List[str]:
        return self._scenario["Subnets"][subnetname]["Hosts"]

    def get_subnet_nacls(self, subnetname: str) -> dict:
        subnet_info = self._scenario["Subnets"][subnetname]
        return subnet_info.get("NACLs", {})

    def get_host_image_name(self, hostname: str) -> str:
        return self._scenario["Hosts"][hostname]["image"]

    def get_host(self, hostname: str) -> dict:
        return self._scenario["Hosts"][hostname]

    def get_host_subnet_names(self, hostname: str) -> List[str]:
        host_subnets = []
        for subnetname in self.subnets:
            if hostname in self.get_subnet_hosts(subnetname):
                host_subnets.append(subnetname)
        return host_subnets

    def get_agent_info(self, agent_name: str) -> ScenarioAgent:
        return self._agents[agent_name]

    def __str__(self):
        return pprint.pformat(self._scenario, depth=2)
