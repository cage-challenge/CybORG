import copy
import inspect
import json
from ipaddress import IPv4Network
from math import log2

import yaml


from CybORG.Shared import Scenario
from CybORG.Simulator.Actions import Monitor
from CybORG.Shared.Scenario import ScenarioHost
from CybORG.Shared.Scenarios.ScenarioGenerator import ScenarioGenerator


class FileReaderScenarioGenerator(ScenarioGenerator):
    """
    The FileReaderScenarioGenerator reads in a file when created and uses that file to create scenarios
    """
    def __init__(self, file_path: str):
        """
        Args:
            file_path: this is the path to the file being used to create the scenario. The file should be in yaml format
        """
        super().__init__()
        self.background = "plain_background"
        self.file_path = file_path

        with open(self.file_path) as fIn:
            scenario_dict = yaml.load(fIn, Loader=yaml.FullLoader)
        from CybORG import CybORG
        cyborg_path = str(inspect.getfile(CybORG))
        images_file_path = cyborg_path[:-7] + '/Simulator/Scenarios/scenario_files/images/'
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
        scenario_dict['team_calcs'] = {agent_name: [(agent_data['reward_calculator_type'], agent_data.get('adversary', None)),] for agent_name, agent_data in scenario_dict['Agents'].items()}
        scenario_dict['team_agents'] = {agent_name: [agent_name] for agent_name, agent_data in scenario_dict['Agents'].items()}
        for agent_name in scenario_dict["Agents"].keys():
            scenario_dict["Agents"][agent_name]["team"] = agent_name
        scenario = Scenario.load(scenario_dict)

        # add in subnet routers as hosts
        for subnet in scenario.subnets.keys():
            scenario.hosts[subnet+'_router'] = ScenarioHost(subnet+'_router', system_info={'OSType': 'linux',
                                                                     "OSDistribution": 'RouterLinux',
                                                                     # TODO replace with correct distro
                                                                     "OSVersion": "unknown",
                                                                     "Architecture": "unknown"
                                                                     }, respond_to_ping=False)
            scenario.subnets[subnet].hosts.append(subnet+'_router')
        if 'Scenario1b' in self.file_path or 'Scenario2' in self.file_path:
            scenario.operational_firewall = True
            for agent_name, agent_data in scenario.agents.items():
                if 'blue' in agent_name.lower():
                    agent_data.default_actions = (Monitor, {'session': 0, 'agent': agent_name})
                else:
                    agent_data.internal_only = True
            with open(f'{cyborg_path[:-7]}/render/render_data_old_scenario.json', 'r') as f:
                data = json.load(f)
            for host in scenario.hosts:
                scenario.hosts[host].starting_position = (data['drones'][host]['x'], data['drones'][host]['y'])
        self.scenario = scenario

    def create_scenario(self, np_random) -> Scenario:
        scenario = copy.deepcopy(self.scenario)

        count = 0
        # randomly generate subnets cidrs for all subnets in scenario and IP addresses for all hosts in those subnets and create Subnet objects
        # using fixed size subnets (VLSM maybe viable alternative if required)
        maximum_subnet_size = max([scenario.get_subnet_size(i) for i in scenario.subnets])
        subnets_cidrs = np_random.choice(
            list(IPv4Network("10.0.0.0/16").subnets(new_prefix=32 - max(int(log2(maximum_subnet_size + 5)), 4))),
            len(scenario.subnets), replace=False)

        # allocate ip addresses and cidrs to interfaces and subnets
        for subnet_name in scenario.subnets:
            # select subnet cidr
            subnet_prefix = 32 - max(int(log2(scenario.get_subnet_size(subnet_name) + 5)), 4)
            subnet_cidr = np_random.choice(list(subnets_cidrs[count].subnets(new_prefix=subnet_prefix)))
            count += 1
            scenario.subnets[subnet_name].cidr = subnet_cidr

            # allocate ip addresses within that subnet
            ip_address_selection = np_random.choice(list(subnet_cidr.hosts()), len(scenario.get_subnet_hosts(subnet_name)), replace=False)
            allocated = 0
            for hostname in scenario.get_subnet_hosts(subnet_name):
                interface_name = f'eth{len(scenario.hosts[hostname].interface_info)}'
                scenario.hosts[hostname].interface_info.append({"name": interface_name,
                                                                           "ip_address": ip_address_selection[allocated],
                                                                           "subnet": subnet_cidr,
                                                                'interface_type': 'wired'})
                if '_router' not in hostname:
                    router_name = subnet_name + '_router'
                    scenario.hosts[hostname].interface_info[-1]['data_links'] = [router_name]
                else:
                    if 'all' in scenario.subnets[subnet_name].nacls:
                        scenario.hosts[hostname].interface_info[-1]['data_links'] = [s_n + '_router' for s_n in scenario.subnets.keys() if s_n != subnet_name]
                    else:
                        scenario.hosts[hostname].interface_info[-1]['data_links'] = [s_n + '_router' for s_n in scenario.subnets[subnet_name].nacls.keys() if s_n != subnet_name]
                allocated += 1
            scenario.subnets[subnet_name].ip_addresses = ip_address_selection

        return scenario


    def __str__(self):
        return f"{self.file_path}"
