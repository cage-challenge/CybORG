# Copyright DST Group. Licensed under the MIT license.
import copy
import inspect
from ipaddress import IPv4Network
from math import log2
from random import sample, choice
import yaml

from CybORG import CybORG
from CybORG.Shared.Actions import FindFlag, ShellSleep, SambaUsermapScript, UpgradeToMeterpreter, MSFEternalBlue, GetShell, \
    PingSweep
from CybORG.Shared.Actions.Action import Action
from CybORG.Shared.Enums import FileType, TrinaryEnum
from CybORG.Shared.EnvironmentController import EnvironmentController
from CybORG.Shared.Observation import Observation
from CybORG.Shared.Results import Results
from CybORG.Simulator.State import State


class SimulationController(EnvironmentController):
    """The class that controls the Simulation environment.

    Inherits from Environment Controller then implements simulation-specific functionality.
    Most methods are either disabled or delegate their functionality to the State attribute.
    The main thing this class currently does is parse the scenario file.
    """
    def __init__(self, scenario_filepath: str = None, scenario_mod: dict = None, agents: dict = None, verbose=True):
        self.state = None
        super().__init__(scenario_filepath, scenario_mod=scenario_mod, agents=agents)

    def reset(self, agent=None):
        self.state.reset()
        self.hostname_ip_map = {h: ip for ip, h in self.state.ip_addresses.items()}
        self.subnet_cidr_map = self.state.subnet_name_to_cidr
        return super(SimulationController, self).reset(agent)

    def pause(self):
        pass

    def execute_action(self, action: Action) -> Observation:
        return action.sim_execute(self.state)

    def restore(self, file: str):
        pass

    def save(self, file: str):
        pass

    def get_true_state(self, info: dict) -> Observation:
        output = self.state.get_true_state(info)
        return output

    def shutdown(self, **kwargs):
        pass

    def _parse_scenario(self, scenario_filepath: str, scenario_mod: dict = None):
        scenario_dict = super()._parse_scenario(scenario_filepath, scenario_mod=scenario_mod)
        images_file_path = str(inspect.getfile(CybORG))
        images_file_path = images_file_path[:-10] + '/Shared/Scenarios/images/'
        with open(images_file_path + 'images.yaml') as fIn:
            images_dict = yaml.load(fIn, Loader=yaml.FullLoader)
        if scenario_dict is not None:
            for hostname, image in scenario_dict["Hosts"].items():
                if 'path' in images_dict[image["image"]]:
                    with open(images_file_path + images_dict[image["image"]]['path'] + '.yaml') as fIn2:
                        scenario_dict["Hosts"][hostname].update(
                            yaml.load(fIn2, Loader=yaml.FullLoader).pop('Test_Host'))
                    image.pop('image')
                else:
                    scenario_dict["Hosts"][hostname] = copy.deepcopy(images_dict[image["image"]])
        return scenario_dict

    def _create_environment(self):
        self.state = State(self.scenario)
        self.hostname_ip_map = {h: ip for ip, h in self.state.ip_addresses.items()}
        self.subnet_cidr_map = self.state.subnet_name_to_cidr

    def run_schtasks(self):
        for host in self.hosts:
            host.run_scheduled_tasks(self.step)

    def get_last_observation(self, agent):
        return self.observation[agent]
