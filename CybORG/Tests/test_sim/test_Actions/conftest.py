import pytest

from CybORG import CybORG
from CybORG.Agents import SleepAgent
from CybORG.Simulator.Actions import ExploitDroneVulnerability, SeizeControl
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator
from CybORG.Tests.utils import AlwaysTrueGenerator


@pytest.fixture(scope='function')
def unattacked_blue():
    # blue has full control of the host and red does not have any code execution on it
    sg = DroneSwarmScenarioGenerator(num_drones=3, starting_num_red=1, max_length_data_links=1000, default_red_agent=SleepAgent, red_internal_only=False)
    cyborg = CybORG(scenario_generator=sg, seed=AlwaysTrueGenerator())
    red_agent = [a for a in cyborg.active_agents if 'red' in a.lower()][0]
    blue_agent = [a for a in cyborg.active_agents if 'blue' in a.lower()][0]
    target_agent = [a for a in cyborg.active_agents if 'blue' in a.lower()][1]
    target_obs = cyborg.get_observation(target_agent)
    target_obs = [obs for obs in target_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    target_host = target_obs['System info']['Hostname']
    target_ip = target_obs['Interface'][0]['IP Address']
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip


@pytest.fixture(scope='function')
def attacked_blue(unattacked_blue):
    # blue has full control of the host but red has low privileged code execution on it
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue
    result = cyborg.step(agent=red_agent, action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    session_id = [i['Sessions'] for i in result.observation.values() if type(i) in (list, dict) and 'Sessions' in i][0][0]['ID']
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id


@pytest.fixture(scope='function')
def unattacked_red(attacked_blue):
    # red has full control of the host and red does not have any low privileged code execution on it
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue
    cyborg.step(agent=red_agent, action=SeizeControl(agent=red_agent, session=0, ip_address=target_ip))
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip


@pytest.fixture(scope='function')
def attacked_red(unattacked_red):
    # red has full control of the host and red has low privileged code execution on it
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_red
    result = cyborg.step(agent=red_agent, action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    session_id = [i['Sessions'] for i in result.observation.values() if type(i) in (list, dict) and 'Sessions' in i][0][0]['ID']
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id


@pytest.fixture(scope='function')
def unattacked_blue_RedDroneAgent():
    # blue has full control of the host and red does not have any code execution on it
    sg = DroneSwarmScenarioGenerator(num_drones=3, starting_num_red=1, max_length_data_links=1000, red_internal_only=False)
    cyborg = CybORG(scenario_generator=sg, seed=1)
    red_agent = [a for a in cyborg.active_agents if 'red' in a.lower()][0]
    blue_agent = [a for a in cyborg.active_agents if 'blue' in a.lower()][0]
    target_agent = [a for a in cyborg.active_agents if 'blue' in a.lower()][1]
    target_obs = cyborg.get_observation(target_agent)
    target_obs = [obs for obs in target_obs.values() if type(obs) in (list, dict) and 'Sessions' in obs][0]
    target_host = target_obs['System info']['Hostname']
    target_ip = target_obs['Interface'][0]['IP Address']
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip

@pytest.fixture(scope='function')
def attacked_blue_RedDroneAgent(unattacked_blue_RedDroneAgent):
    # blue has full control of the host but red has low privileged code execution on it
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_blue_RedDroneAgent
    result = cyborg.step(agent=red_agent, action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    session_id = [i['Sessions'] for i in result.observation.values() if type(i) in (list, dict) and 'Sessions' in i][0][0]['ID']
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id


@pytest.fixture(scope='function')
def unattacked_red_RedDroneAgent(attacked_blue_RedDroneAgent):
    # red has full control of the host and red does not have any low privileged code execution on it
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id = attacked_blue_RedDroneAgent
    cyborg.step(agent=red_agent, action=SeizeControl(agent=red_agent, session=0, ip_address=target_ip))
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip


@pytest.fixture(scope='function')
def attacked_red_RedDroneAgent(unattacked_red_RedDroneAgent):
    # red has full control of the host and red has low privileged code execution on it
    cyborg, red_agent, blue_agent, target_agent, target_host, target_ip = unattacked_red_RedDroneAgent
    result = cyborg.step(agent=red_agent, action=ExploitDroneVulnerability(agent=red_agent, session=0, ip_address=target_ip))
    session_id = [i['Sessions'] for i in result.observation.values() if type(i) in (list, dict) and 'Sessions' in i][0][0]['ID']
    return cyborg, red_agent, blue_agent, target_agent, target_host, target_ip, session_id

