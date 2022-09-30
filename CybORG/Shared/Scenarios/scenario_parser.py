# TODO: create a scenario parser to check scenarios are valid
import yaml

from CybORG.Shared.Scenarios.images.image_parser import parse_image


def parse_scenario_file(scenario_file):
    print(f'Parsing {scenario_file}')
    with open(scenario_file) as fIn:
        loaded_scenario = yaml.load(fIn, Loader=yaml.FullLoader)
    parse_scenario(loaded_scenario)


def parse_scenario(scenario):
    # parse hosts in scenario
    count = 0
    assert 'Hosts' in scenario
    for host in scenario['Hosts'].values():
        parse_host(host)
        count += 1
    print(f'Parsed {count} hosts in scenario')
    host_list = list(scenario['Hosts'].keys())

    # parse subnets in scenario
    count = 0
    assert 'Subnets' in scenario
    subnet_list = list(scenario['Subnets'].keys())
    for subnet in scenario['Subnets'].values():
        parse_subnet(subnet, host_list, subnet_list)
        count += 1
    print(f'Parsed {count} subnets in scenario')

    # parse agents in scenario
    count = 0
    assert 'Agents' in scenario
    for agent in scenario['Agents'].values():
        parse_agent(agent, host_list, subnet_list)
        count += 1
    print(f'Parsed {count} agents in scenario')




def parse_agent(agent, hostlist, subnetlist):
    assert 'AllowedSubnets' in agent
    for subnet in agent['AllowedSubnets']:
        assert subnet in subnetlist, f'subnet {subnet} not in subnet list'
    assert 'INT' in agent
    if 'Hosts' in agent['INT']:
        for host, intelligence in agent['INT']['Hosts'].items():
            assert host in hostlist, f'host {host} in INT not in host list'
    assert 'actions' in agent
    assert 'agent_type' in agent
    assert 'reward_calculator_type' in agent
    assert 'starting_sessions' in agent
    for session in agent['starting_sessions']:
        assert session['hostname'] in hostlist, f'hostname {session["hostname"]} for session {session["name"]} not in hostlist'
    assert 'wrappers' in agent


def parse_host(host):
    assert 'image' in host
    parse_image(host['image'])


def parse_subnet(subnet, host_list, subnet_list):
    assert 'Hosts' in subnet
    for host in subnet['Hosts']:
        assert host in host_list
    assert 'NACLs' in subnet
    for name, rule in subnet['NACLs'].items():
        if name != 'all':
            assert name in subnet_list
    assert 'Size' in subnet

if __name__ == "__main__":
    for scenario in ["Scenario1.yaml", "Scenario1b.yaml"]:
        parse_scenario_file(scenario)
