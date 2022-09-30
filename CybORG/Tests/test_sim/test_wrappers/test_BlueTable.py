import pytest
import inspect
from ipaddress import IPv4Address, IPv4Network

from prettytable import PrettyTable
import numpy as np

from CybORG import CybORG
from CybORG.Shared.Actions import Remove
from CybORG.Shared.Enums import TrinaryEnum
from CybORG.Agents.SimpleAgents.B_line import B_lineAgent
from CybORG.Agents.Wrappers.BlueTableWrapper import BlueTableWrapper
from CybORG.Shared.Actions.AbstractActions import Monitor
from CybORG.Agents import BlueMonitorAgent

def get_table(rows):    
    table = PrettyTable([    
        'Subnet',    
        'IP Address',    
        'Hostname',    
        'Activity',
        'Compromised',    
        ])    
    for r in rows:
        table.add_row(rows[r])

    table.sortby = 'Hostname'
    return table    

@pytest.mark.skip
def test_BlueTableWrapper():
    path = str(inspect.getfile(CybORG))    
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'    
    
    cyborg = BlueTableWrapper(env=CybORG(path, 'sim',agents={'Red': B_lineAgent}))
    agent_name = 'Blue'

    def get_ip(host):
        ip_map = cyborg.env.env.environment_controller.state.ip_addresses
        for ip in ip_map:
            if ip_map[ip] == host:
                return str(ip)
        raise ValueError('Searched for host with no ip address. Probably invalid hostname.')

    def get_subnet(subnet):
        cidr_map = cyborg.env.env.environment_controller.state.subnet_name_to_cidr
        return str(cidr_map[subnet])

    def get_generic_rows():
        generic_rows = {}
        for i in range(5):
            host = 'User' + str(i)
            generic_rows[host] = [get_subnet('User'),get_ip(host),host,
                    'None', 'No']
        for i in range(3):
            host = 'Enterprise' + str(i)
            generic_rows[host] = [get_subnet('Enterprise'),get_ip(host),host,
                    'None','No']
        host = 'Defender'
        generic_rows[host] = [get_subnet('Enterprise'), get_ip(host), host,
                              'None', 'No']
        for i in range(3):
            host = 'Op_Host' + str(i)
            generic_rows[host] = [get_subnet('Operational'),get_ip(host),host,
                    'None','No']

        host = 'Op_Server0'
        generic_rows[host] = [get_subnet('Operational'),get_ip(host),host,
                    'None','No']
        host = 'Defender'
        generic_rows[host] = [get_subnet('Enterprise'),get_ip(host),host,
                    'None','No']

        return generic_rows

    # Test Initial Observation
    results = cyborg.reset(agent=agent_name)
    observation = results.observation

    expected_rows = get_generic_rows()
    expected_table = get_table(expected_rows)

    # We compare strings instead of tables. See comments in get_table function.
    assert observation.get_string() == expected_table.get_string()

    # Test New Host Discovery
    action = Monitor(agent='Blue',session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum.TRUE
    assert observation.success == expected_success

    expected_rows = get_generic_rows()

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Port Scan
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum.TRUE
    assert observation.success == expected_success

    expected_rows['User1'][3] = 'Scan'

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Remote Exploit
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum.TRUE
    assert observation.success == expected_success

    expected_rows['User1'][3] = 'Exploit'
    expected_rows['User1'][-1] = 'User'
    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Privilege Escalate
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum.TRUE
    assert observation.success == expected_success

    expected_rows['User1'][3] = 'None'
    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Remove
    action = Remove(hostname='User1',agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum.TRUE
    assert observation.success == expected_success

    expected_rows['User1'][-1] = 'Unknown'
    expected_rows['Enterprise1'][-2] = 'Scan'
    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Remove on Non Compromised Host
    action = Remove(hostname='User2', agent=agent_name, session=0)
    results = cyborg.step(action=action,agent=agent_name)
    
    observation = results.observation

    expected_success = TrinaryEnum.TRUE
    assert observation.success == expected_success

    expected_rows['Enterprise1'][-2] = 'Exploit'
    expected_rows['Enterprise1'][-1] = 'User'
    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

def test_blue_vector():
    path = str(inspect.getfile(CybORG))    
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'    
    
    cyborg = BlueTableWrapper(env=CybORG(path, 'sim',agents = {'Red':B_lineAgent}), output_mode='vector')    
    agent_name = 'Blue'
    results = cyborg.reset(agent=agent_name)
    observation = results.observation

    expected_vector = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0])

    assert all(observation == expected_vector)

    for i in range(10):
        action = Monitor(session=0,agent='Blue')
        results = cyborg.step(action=action,agent='Blue')
        assert type(results.observation) == type(expected_vector)
        assert len(results.observation) == len(expected_vector)

@pytest.fixture(params=['table','raw'])
def cyborg(request,agents = {'Blue':BlueMonitorAgent,'Red':B_lineAgent},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = BlueTableWrapper(env=CybORG(path, 'sim', agents=agents),output_mode=request.param)
    cyborg.set_seed(seed)
    return cyborg

def test_get_attr(cyborg):
    for attribute in ['get_observation','get_action_space','get_last_action','get_ip_map',
            'get_rewards', 'get_agent_state']:
        assert cyborg.get_attr(attribute) == cyborg.env.get_attr(attribute)

def test_get_observation(cyborg):
    step_obs= cyborg.reset(agent='Red').observation
    method_obs = cyborg.get_observation('Red')
    assert step_obs == method_obs

    step_obs= cyborg.step(agent='Red').observation
    method_obs = cyborg.get_observation('Red')
    assert step_obs == method_obs

    step_obs = cyborg.reset(agent='Blue').observation
    method_obs = cyborg.get_observation('Blue')
    if type(step_obs) != dict:
        step_obs = step_obs.get_string()
        method_obs = method_obs.get_string()

    assert step_obs == method_obs

    step_obs = cyborg.step(agent='Blue').observation
    method_obs = cyborg.get_observation('Blue')
    if type(step_obs) != dict:
        step_obs = step_obs.get_string()
        method_obs = method_obs.get_string()
    assert step_obs == method_obs

def test_get_agent_state(cyborg):
    cyborg.reset()
    cyborg.step()
    assert cyborg.get_agent_state('True') == cyborg.get_attr('get_agent_state')('True')
    assert cyborg.get_agent_state('Red') == cyborg.get_attr('get_agent_state')('Red')
    assert cyborg.get_agent_state('Blue') == cyborg.get_attr('get_agent_state')('Blue')

def test_get_action_space(cyborg):
    assert cyborg.get_action_space('Red') == cyborg.get_attr('get_action_space')('Red')
    assert cyborg.get_action_space('Blue') == cyborg.get_attr('get_action_space')('Blue')

def test_get_last_action(cyborg):
    cyborg.reset()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')
    cyborg.step()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')

def test_get_ip_map(cyborg):
    assert cyborg.get_ip_map() == cyborg.get_attr('get_ip_map')()

def test_get_rewards(cyborg):
    assert cyborg.get_rewards() == cyborg.get_attr('get_rewards')()
