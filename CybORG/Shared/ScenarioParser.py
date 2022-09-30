# Copyright DST Group. Licensed under the MIT license.

"""
This module contains functions for parsing a YAML scenario config file
"""
import os
import yaml
from copy import deepcopy
from prettytable import PrettyTable

from CybORG.Shared.State.Credentials import AccessLevel, Credentials
from CybORG.Shared.State.Service import Service, ServiceType
from CybORG.Shared.State.OperatingSystem import OperatingSystemType, OperatingSystemInformation

path = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.join(os.path.dirname(path), os.pardir)

# file path to available actions list
AVAIL_ACTIONS_PATH = os.path.join(path, '../Simulator/Actions', 'Actions.yaml')

# file path to available images list
AVAIL_IMAGES_PATH = os.path.join(path, 'Images', 'Images.yaml')

# The expected properties of a scenario config file
SCENARIO_KEYS_REQ = ["Subnets", "Hosts"]
SCENARIO_KEYS_OPT = ["RedActions"]

# Expected keys for each host
HOST_KEYS_REQ = ["subnet", "image"]
HOST_KEYS_OPT = ["value"]

# Optional params and default values for red actions
RED_ACTION_OPT = {
    "success_prob": 1,
    "cost": 0,
    "detect_prob": 0}

INT_host_list = ["IPs", "Subnets", "Creds", "OS_info", "Services", "Flag"]
INT_subnet_list = ["CIDR"]

# TODO parse simplicity of password

def load_yaml(file_path):
    """
    Load file located at file path, throws error if theres an issue loading
    file.

    Arguments:
        file_path : path to YAML scenario config file

    Returns:
        scenario : the scenario file as a dict
    """
    with open(file_path) as fIn:
        scenario_file = yaml.load(fIn, Loader=yaml.FullLoader)
    return scenario_file


def parse_scenario_file(scenario_file_path):
    """
    Load and parse a YAML scenario file.
    Throws exceptions if error loading file or file format is incorrect.

    Arguments:
        scenario_file_path : path to YAML scenario config file

    Returns:
        parsed_scenario : the parsed scenario as a dict
    """
    scenario = load_yaml(scenario_file_path)

    check_scenario_keys_correct(scenario)

    avail_actions = load_yaml(AVAIL_ACTIONS_PATH)
    avail_images_yaml = load_yaml(AVAIL_IMAGES_PATH)
    avail_images = parse_images(avail_images_yaml)

    scn_name = get_scenario_name(scenario_file_path)
    parsed_subnets = parse_subnets(scenario["Subnets"])
    parsed_hosts, num_hosts_with_pos_val = parse_hosts(scenario["Hosts"], parsed_subnets, avail_images)

    if "RedActions" not in scenario.keys():
        parsed_red_actions = load_default_red_action_dict(avail_actions["RedActions"])
    else:
        parsed_red_actions = parse_red_action_dict(scenario["RedActions"], avail_actions["RedActions"])

    if "OSINT" not in scenario.keys():
        parsed_OSINT = load_default_OSINT_dict(parsed_hosts)
    else:
        parsed_OSINT = parse_OSINT_dict(scenario["OSINT"], parsed_hosts, parsed_subnets)

    parsed_scenario = {"Name": scn_name,
                       "Hosts": parsed_hosts,
                       "Flags": num_hosts_with_pos_val,
                       "Subnets": parsed_subnets,
                       "RedActions": parsed_red_actions,
                       "OSINT": parsed_OSINT}

    return parsed_scenario


def check_scenario_keys_correct(scenario):
    """
    Checks the scenario contains all the necessary high-level keys in
    SCENARIO_KEYS

    Raises error if key incorrect or missing
    """
    for req_key in SCENARIO_KEYS_REQ:
        if req_key not in scenario.keys():
            raise KeyError("Scenario: Missing required key in scenario config file: {}".format(req_key))


def get_scenario_name(scenario_file_path):
    """
    Get the scenario name from the scenario file path.

    Arguments:
        str scenario_file_path : path to YAML scenario config file

    Returns:
        str scenario_name : name of scenario
    """
    return os.path.basename(scenario_file_path).replace('.yaml', '')


def parse_images(images):
    """
    Parses list of available images into Image objects.

    Arguments:
        images : dictionary of images

    Returns:
        parsed_images : dictionary of parsed images
    """
    parsed_images = {}
    for image_name, image_info in images.items():
        name = image_info["Name"]
        image_id = image_info["Image_ID"]

        os_data = image_info["OS"]
        os_type = OperatingSystemType.parse_string(os_data["Type"])
        os_dist = os_data["Distribution"]
        os_version = os_data["Version"]
        os_info = OperatingSystemInformation(os_type, os_dist, os_version)

        services = []
        for service_name, service_info in image_info["Services"].items():
            service_type = ServiceType.parse_string(service_name)
            port = service_info["port"]
            state = service_info.get("state", "open")
            version = service_info.get("version", "")
            services.append(Service(service_type, port, state, version))

        credentials = []
        for uname, access_info in image_info["Credentials"].items():
            access_level = AccessLevel.parseString(access_info["Access"])
            password = access_info.get("Password")
            key_path = access_info.get("Key")
            simplicity = access_info.get("Simplicity")
            creds = Credentials(username=uname, password=password, key_path=key_path,
                                access_level=access_level, simplicity=simplicity)
            credentials.append(creds)

        # Process AWS Instance type if there is one
        inst_type = image_info.get("AWS_Instance_Type", None)

        # Whether an SSH key is required for access to image, False by default
        key_access = image_info.get("Key_Access", False)

        image = Image(name, services, image_id, os_info, credentials, inst_type, key_access)
        parsed_images[image_name] = image

    return parsed_images


def parse_subnets(subnets):
    """
    Parse the Subnets dict, checking it is in correct format.
    Raises errors if there is a format violation.

    Arguments:
        subnets : the subnets dict

    Returns:
        parsed_subnets : parsed Subnet dict
    """
    if not isinstance(subnets, dict):
        raise ValueError("Subnets must be dict with key-value pairs: {}"
                         .format("subnet_id : [subnet_id, ..., subnet_id]"))

    if len(subnets) < 2:
        raise ValueError("Not enough subnets specified, need at least two:",
                         "one for attacker and one for target")

    parsed_subnets = {}
    avail_subnets = set(subnets.keys())
    for subnet_id, connected_list in subnets.items():
        if not isinstance(connected_list, list) or len(connected_list) < 1:
            raise ValueError("Subnet values must be list with at least one entry {} is invalid"
                             .format(connected_list))

        if subnet_id in connected_list:
            raise ValueError("Subnet connected list should not contain parent subnet: {}: {} invalid"
                             .format(subnet_id, connected_list))

        for connected_id in connected_list:
            if connected_id not in avail_subnets:
                raise ValueError("Subnets can only be connected to subnets with specified in top",
                                 "level subnet list: for subnet {} connected subnet {} invalid"
                                 .format(subnet_id, connected_id))

            if connected_list.count(connected_id) > 1:
                raise ValueError("Connected subnet lists cannot have duplicates: {}: {} invalid"
                                 .format(subnet_id, connected_list))
        parsed_subnets[subnet_id] = connected_list

    return parsed_subnets


def parse_hosts(hosts, subnets, avail_images):
    """
    Parse the Hosts dict, checking it is in correct format.
    Raises errors if there is a format violation.

    Arguments:
        hosts : the hosts dict
        subnets : the parsed subnets dictionary
        avail_images : the available images dictionary

    Returns:
        parsed_hosts : the parsed hosts dict
        num_hosts_with_pos_val : the number of hosts with a value
    """
    if not isinstance(hosts, dict):
        raise ValueError("Hosts: Hosts must be dict with key-values - host_ID: {}, plus optional params {}"
                         .format(HOST_KEYS_REQ, HOST_KEYS_OPT))

    if len(hosts) < 2:
        raise ValueError("Hosts: Not enough hosts specified (need at least one attacker and one host)")

    parsed_hosts = {}
    num_hosts_with_pos_val = 0
    for host_id, params in hosts.items():

        for req_key in HOST_KEYS_REQ:
            if req_key not in params:
                raise ValueError("Hosts: Host {} missing required parameter {}".format(host_id, req_key))

        parsed_host = {}
        subnet = params['subnet']
        if subnet not in subnets:
            raise ValueError("Hosts: Host subnet must be a subnet in scenario subnets: {} invalid".format(subnet))

        image = params['image']
        if image not in avail_images:
            raise ValueError(f"Hosts: Host VM image must be an image name from available VM image list: host {host_id} "
                             f"image {image} invalid.\nSee {AVAIL_IMAGES_PATH} file for list of available images")

        if "value" in params:
            value = params["value"]
            if not isinstance(value, (int, float)):
                raise ValueError("Hosts: Host value must be a valid integer or float: host {} value {} invalid"
                                 .format(host_id, value))
            value = int(value) if isinstance(value, int) else float(value)
            if value > 0:
                num_hosts_with_pos_val += 1
        else:
            value = 0

        parsed_host['subnet'] = subnet
        parsed_host['value'] = value
        parsed_host['image'] = avail_images[image]
        parsed_hosts[host_id] = parsed_host
        parsed_host['configuration'] = params.get('configuration', [])

    if num_hosts_with_pos_val < 1:
        raise ValueError("Hosts: At least one host must have a positive value (i.e. contain a goal)")

    return parsed_hosts, num_hosts_with_pos_val


def load_default_red_action_dict(avail_actions):
    """
    Loads all the available red actions for the CybORG environment with default parameter values.

    See Actions/Actions.yaml list for full list of available actions

    Arguments:
        avail_actions : dictionary of all available actions with names as keys and extra info as values

    Returns:
        parsed_actions : the parsed actions dict
    """
    print("RedActions: No actions specified so using list of all available actions with default params: {}"
          .format(RED_ACTION_OPT))

    parsed_actions = {}
    # for action_name, action_info in avail_actions.items():
    for action_name in avail_actions:
        parsed_params = deepcopy(RED_ACTION_OPT)
        parsed_params["name"] = action_name
        # for action_property, property_value in action_info.items():
        #     parsed_params[action_property] = property_value
        parsed_actions[action_name] = parsed_params
    return parsed_actions


def parse_red_action_dict(action_dict, valid_actions):
    """
    Parse the Red Actions dict.
    Raises excepted for any format violations

    Arguments:
        action_dict : the action dict to parse
        valid_actions : dictionary of valid actions with names as keys and extra info as values

    Returns:
        parsed_actions : the parsed actions dict
    """
    if not isinstance(action_dict, dict):
        raise ValueError("RedActions: Actions must be dict with key-value pairs: "
                         + "action_name : {action_param: value, ...}")

    for action_name in action_dict.keys():
        if action_name not in valid_actions:
            raise ValueError("RedActions: red can only choose actions from Actions list. {} invalid"
                             .format(action_name)
                             + "\nFor full list of actions see {}".format(AVAIL_ACTIONS_PATH))

    parsed_actions = {}
    for action_name, params in action_dict.items():
        if not isinstance(params, dict):
            raise ValueError("RedActions: Action parameters must be dict with key-value pairs: "
                             + "action_param: value. {}: {} is invalid. ".format(action_name, params)
                             + "\nIf you would like to use default values enter empty dictionary as '{}': "
                             + "e.g. Get_host_os: {}")

        parsed_params = {"type": valid_actions[action_name]}
        # parsed_params["name"] = action_name
        for action_param, value in params.items():
            parsed_value = None
            if action_param == "success_prob":
                parsed_value = float(value)
                if 0 > parsed_value or parsed_value > 1:
                    raise ValueError('RedActions: action param "success_prob" must have value from 0 to 1.',
                                     "Value {} for action {} invalid".format(value, action_name))

            if action_param == "cost":
                if not isinstance(value, (int, float)):
                    raise ValueError('RedActions: action param "cost" must be a int or float.'
                                     + "Value {} for action {} invalid".format(value, action_name))
                parsed_value = float(value)
                if parsed_value < 0:
                    print("RedActions: Warning: negative action cost detected for action {}.".format(action_name),
                          "Action costs are typically handled as a non-negative value. Change the scenario file if",
                          "this is an incorrect value, otherwise ignore this warning.")

            parsed_params[action_param] = parsed_value

        for opt_param, default_value in RED_ACTION_OPT.items():
            if opt_param not in parsed_params:
                parsed_params[opt_param] = default_value

        # for action_property, property_value in valid_actions[action_name].items():
        #     parsed_params[action_property] = property_value

        parsed_actions[action_name] = parsed_params

    return parsed_actions


def load_default_OSINT_dict(avail_hosts):
    """
    Loads the default OSINT for the CybORG environment.

    Arguments:
        avail_hosts : dictionary of all available hosts with names as keys and extra info as values

    Returns:
        parsed_OSINT : the parsed OSINT dict
    """
    print("OSINT: No OSINT specified so using publicly facing hosts")

    parsed_OSINT = {}
    # for action_name, action_info in avail_actions.items():
    for host in avail_hosts.keys():
        if "PublicFacing" in host:
            parsed_OSINT[host] = "IP"

    return parsed_OSINT


def parse_OSINT_dict(OSINT_dict, avail_hosts, avail_subnets):
    """
    Parse the Red Actions dict.
    Raises excepted for any format violations

    Arguments:
        action_dict : the action dict to parse
        valid_actions : dictionary of valid actions with names as keys and extra info as values

    Returns:
        parsed_actions : the parsed actions dict
        :param subnets:
    """
    if not isinstance(OSINT_dict, dict):
        raise ValueError("OSINT: OSINT must be dict with key-value pairs")

    parsed_OSINT = {}
    if "Hosts" in OSINT_dict:
        parsed_OSINT["Hosts"] = {}
        for host, l in OSINT_dict["Hosts"].items():
            if host in avail_hosts.keys():
                parsed_values = []
                if l is not None:
                    for v in l:
                        if v in INT_host_list:
                            parsed_values.append(v)
                        else:
                            raise ValueError("OSINT: intelligence on {} unavaliable".format(v))
                parsed_OSINT["Hosts"][host] = parsed_values
            else:
                raise ValueError("OSINT: Host {} specified by OSINT not found in scenario".format(host))
    if "Subnets" in OSINT_dict:
        parsed_OSINT["Subnets"] = {}
        for subnet, l in OSINT_dict["Subnets"].items():
            if subnet in avail_subnets.keys():
                parsed_values = []
                if l is not None:
                    for v in l:
                        if v in INT_subnet_list:
                            parsed_values.append(v)
                        else:
                            raise ValueError("OSINT: intelligence on {} unavaliable".format(v))
                parsed_OSINT["Subnets"][subnet] = parsed_values
            else:
                raise ValueError("OSINT: Subnet {} specified by OSINT not found in scenario".format(subnet))
    return parsed_OSINT

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--file_path", type=str, default='./Scenarios/scenario_6_hosts.yaml',
                        help="file path of scenario YAML file (e.g. './scenario_0.yaml')")
    args = parser.parse_args()

    print(f"Parsing scenario file {args.file_path}")
    parsed_scenario = parse_scenario_file(args.file_path)
    print("Parsing complete")

    for k, v in parsed_scenario.items():
        table = PrettyTable()
        table.title = k
        if k == "Subnets":
            table.field_names = ["Name", "ConnectedTo"]
            for subnet, connected in v.items():
                table.add_row([subnet] + [connected])
            print(f"\n{table}\n")
            print("-" * 80 + "\n")
        elif k == "Hosts":
            print("\n{}\nHosts:\n".format("-"*80))
            for name, vals in v.items():
                print(f"Name: {name}")
                for prop, prop_val in vals.items():
                    print(f"\t{prop}: {prop_val}")
                print("\n")
            print("-"*80 + "\n")
            continue
        elif k == "Name":
            print(v)
        elif k == "OSINT":
            print("OSINT: ")
            print(v)
        elif k == "Flags":
            print(f"Number of flags: {v}")
        else:
            for name, vals in v.items():
                table = PrettyTable()
                headers = list(vals.keys())
                table.field_names = headers
                table.add_row(list(vals.values()))
                print(f"\n{table}\n")
