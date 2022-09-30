import inspect

import pytest

from CybORG import CybORG
from .scenario_fixtures.scenario_fixtures import SCENARIOS
from CybORG.Agents.Utils import RedAgentBelief
from CybORG.Agents import SleepAgent
from CybORG.Simulator.Scenarios import FileReaderScenarioGenerator, DroneSwarmScenarioGenerator


def create_cyborg_file(scenario_name, blue_agent):
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/{scenario_name}.yaml'

    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(scenario_generator=sg, agents={'Blue':blue_agent()})

    return cyborg

def create_cyborg_drones(scenario_name, blue_agent):
    sg = DroneSwarmScenarioGenerator(max_length_data_links=1000, red_internal_only=False, starting_num_red=1)
    cyborg = CybORG(scenario_generator=sg)

    return cyborg


def create_cyborg(scenario_name, blue_agent=SleepAgent):
    is_drones = scenario_name.lower() == 'scenario3'
    scenario_function = create_cyborg_drones if is_drones else create_cyborg_file
    return scenario_function(scenario_name, blue_agent)


def compromised_cyborg(scenario_name, stop_host, stop_value):
    # stop_value: 0 = Known, 1 = Scanned, 2 = User Acess, 3 = Priviliged Access
    cyborg = create_cyborg(scenario_name)
    results = cyborg.reset(agent='Red')
    ip_map = cyborg.get_ip_map()

    belief = RedAgentBelief()
    belief.update(results.observation, action=None)

    for host in SCENARIOS[scenario_name]['Hosts']:
        history = []
        if host == 'Defender':
            continue

        unscanned_subnets = belief.unscanned_subnets
        if len(unscanned_subnets) > 0:
            subnet = str(unscanned_subnets[0])
            action = belief.subnets[subnet].next_action
            results = cyborg.step(agent='Red', action=action)
            belief.update(results.observation, action=action)
            history.append(action)

        ip = str(ip_map[host])
        host_belief = belief.hosts.get(ip)
        status = host_belief.status
        if (host == stop_host) and (status.value >= stop_value):
            break

        if host_belief is None:
            raise ValueError('Red belief does not know host. Order must be changed.')

        for i in range(10):
            action = host_belief.next_action
            results = cyborg.step(agent='Red', action=action)
            belief.update(results.observation, action=action)
            history.append(action)

            status = host_belief.status
            if (host == stop_host) and (status.value == stop_value):
                break
            elif status.value == 3:
                break
        else:
            raise ValueError('Red Action failed after multiple attempts.')

        if host == stop_host:
            break

    cyborg.history = history

    return cyborg

def subnet_scanner(scenario_name, stop_subnet):
    # stop_value: 0 = Known, 1 = Scanned, 2 = User Acess, 3 = Priviliged Access
    cyborg = create_cyborg(scenario_name)
    results = cyborg.reset(agent='Red')
    ip_map = cyborg.get_ip_map()
    cidr = cyborg.get_cidr_map()[stop_subnet]

    belief = RedAgentBelief()
    belief.update(results.observation, action=None)

    for host in SCENARIOS[scenario_name]['Hosts']:
        if host == 'Defender':
            continue

        unscanned_subnets = belief.unscanned_subnets
        if len(unscanned_subnets) > 0:
            if unscanned_subnets[0] == cidr:
                return cyborg

            subnet = str(unscanned_subnets[0])
            action = belief.subnets[subnet].next_action
            results = cyborg.step(agent='Red', action=action)
            belief.update(results.observation, action=action)

        ip = str(ip_map[host])
        host_belief = belief.hosts.get(ip)
        status = host_belief.status

        if host_belief is None:
            raise ValueError('Red belief does not know host. Order must be changed.')

        for i in range(10):
            action = host_belief.next_action
            results = cyborg.step(agent='Red', action=action)
            belief.update(results.observation, action=action)

            status = host_belief.status
            if status.value == 3:
                break
        else:
            raise ValueError('Red Action failed after multiple attempts.')

    return cyborg

def blue_observation_history(scenario_name, blue_agent=SleepAgent):
    cyborg = create_cyborg(scenario_name, blue_agent)
    results = cyborg.reset(agent='Red')
    ip_map = cyborg.get_ip_map()

    belief = RedAgentBelief()
    belief.update(results.observation, action=None)

    history = []
    for host in SCENARIOS[scenario_name]['Hosts']:
        if host == 'Defender':
            continue

        unscanned_subnets = belief.unscanned_subnets
        if len(unscanned_subnets) > 0:
            subnet = str(unscanned_subnets[0])
            action = belief.subnets[subnet].next_action
            results = cyborg.step(agent='Red', action=action)
            belief.update(results.observation, action=action)
            history.append((action, cyborg.get_observation('Blue')))

        ip = str(ip_map[host])
        host_belief = belief.hosts.get(ip)
        status = host_belief.status

        if host_belief is None:
            raise ValueError('Red belief does not know host. Order must be changed.')

        for i in range(10):
            action = host_belief.next_action
            results = cyborg.step(agent='Red', action=action)
            belief.update(results.observation, action=action)
            history.append((action, cyborg.get_observation('Blue')))

            status = host_belief.status
            if status.value == 3:
                break
        # else:
        #     raise ValueError('Red Action failed after multiple attempts.')

    return history
