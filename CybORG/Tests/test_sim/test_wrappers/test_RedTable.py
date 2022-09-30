import pytest
import inspect
from ipaddress import IPv4Address, IPv4Network

from prettytable import PrettyTable
import numpy as np

from CybORG import CybORG
from CybORG.Agents.SimpleAgents.BlueReactAgent import BlueReactRemoveAgent
from CybORG.Shared.Enums import TrinaryEnum
from CybORG.Agents.Wrappers.RedTableWrapper import RedTableWrapper
from CybORG.Shared.Actions.AbstractActions import DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, PrivilegeEscalate, Impact
from CybORG.Agents import BlueMonitorAgent, B_lineAgent


def get_table(rows):    
    table = PrettyTable([    
        'Subnet',    
        'IP Address',    
        'Hostname',    
        'Scanned',    
        'Access',    
        ])    
    for r in rows:
        table.add_row(r)

    table.sortby = 'IP Address'
    return table    

@pytest.mark.skip
def test_RedTableWrapper():
    path = str(inspect.getfile(CybORG))    
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'    
    
    cyborg = RedTableWrapper(env=CybORG(path, 'sim'), output_mode='table')    
    agent_name = 'Red'

    def get_ip(host):
        ip_map = cyborg.env.env.environment_controller.state.ip_addresses
        for ip in ip_map:
            if ip_map[ip] == host:
                return str(ip)
        raise ValueError('Searched for host with no ip address. Probably invalid hostname.')

    def get_subnet(subnet):
        cidr_map = cyborg.env.env.environment_controller.state.subnet_name_to_cidr
        return str(cidr_map[subnet])

    # Test Initial Observation
    results = cyborg.reset(agent=agent_name)
    observation = results.observation

    # Success tested separately. See comments in get_table function.
    expected_success = TrinaryEnum(2) # UNKNOWN
    assert observation.success == expected_success 

    expected_rows = [[get_subnet('User'),get_ip('User0'),'User0',False,'Privileged']]
    expected_table = get_table(expected_rows)

    # We compare strings instead of tables. See comments in get_table function.
    assert observation.get_string() == expected_table.get_string()

    # Test New Host Discovery
    subnet = IPv4Network(get_subnet('User'))
    action = DiscoverRemoteSystems(subnet=subnet, agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(1) # TRUE
    assert observation.success == expected_success

    expected_rows = [[get_subnet('User'),get_ip('User0'),'User0',False,'Privileged']]
    for i in range(1,5):
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: '+str(i-1)
        expected_rows.append([get_subnet('User'),get_ip(host),host_table,False,'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Port Scan
    ip_address = IPv4Address(get_ip('User1'))
    action = DiscoverNetworkServices(ip_address=ip_address, agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(1) # TRUE
    assert observation.success == expected_success

    expected_rows = [
            [get_subnet('User'),get_ip('User0'),'User0',False,'Privileged'],
            [get_subnet('User'),get_ip('User1'),'UNKNOWN_HOST: 0',True,'None']
            ]
    for i in range(2,5):
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: '+str(i-1)
        expected_rows.append([get_subnet('User'),get_ip(host),host_table,False,'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Remote Exploit
    ip_address = IPv4Address(get_ip('User1'))
    action = ExploitRemoteService(ip_address=ip_address, agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(1) # TRUE
    assert observation.success == expected_success

    expected_rows = [
            [get_subnet('User'),get_ip('User0'),'User0',False,'Privileged'],
            [get_subnet('User'),get_ip('User1'),'User1',True,'User']
            ]
    for i in range(2,5):
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: '+str(i-1)
        expected_rows.append([get_subnet('User'),get_ip(host),host_table,False,'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Privilege Escalate
    action = PrivilegeEscalate(hostname='User1', agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(1) # TRUE
    assert observation.success == expected_success

    expected_rows = [
            [get_subnet('User'),get_ip('User0'),'User0',False,'Privileged'],
            [get_subnet('User'),get_ip('User1'),'User1',True,'Privileged']
            ]
    for i in range(2,5):
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: '+str(i-1)
        expected_rows.append([get_subnet('User'),get_ip(host),host_table,False,'None'])

    expected_rows.append(['UNKNOWN_SUBNET: 4',get_ip('Enterprise1'),'UNKNOWN_HOST: 5',
        False,'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Failed Action
    action = Impact(hostname='User0',agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(3) # FALSE
    assert observation.success == expected_success 

    # Expected table same as previous
    assert observation.get_string() == expected_table.get_string()

@pytest.mark.skip
def test_RedTableWrapper_blue_remove_agent():

    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'

    cyborg = RedTableWrapper(env=CybORG(path, 'sim', agents={'Blue': BlueReactRemoveAgent}), output_mode='table')
    cyborg.set_seed(0)
    agent_name = 'Red'

    def get_ip(host):
        ip_map = cyborg.env.env.environment_controller.state.ip_addresses
        for ip in ip_map:
            if ip_map[ip] == host:
                return str(ip)
        raise ValueError('Searched for host with no ip address. Probably invalid hostname.')

    def get_subnet(subnet):
        cidr_map = cyborg.env.env.environment_controller.state.subnet_name_to_cidr
        return str(cidr_map[subnet])

    # Test Initial Observation
    results = cyborg.reset(agent=agent_name)
    observation = results.observation

    # Success tested separately. See comments in get_table function.
    expected_success = TrinaryEnum(2)  # UNKNOWN
    assert observation.success == expected_success

    expected_rows = [[get_subnet('User'), get_ip('User0'), 'User0', False, 'Privileged']]
    expected_table = get_table(expected_rows)

    # We compare strings instead of tables. See comments in get_table function.
    assert observation.get_string() == expected_table.get_string()

    # Test New Host Discovery
    subnet = IPv4Network(get_subnet('User'))
    action = DiscoverRemoteSystems(subnet=subnet, agent=agent_name, session=0)
    results = cyborg.step(action=action, agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(1)  # TRUE
    assert observation.success == expected_success

    expected_rows = [[get_subnet('User'), get_ip('User0'), 'User0', False, 'Privileged']]
    for i in range(1, 5):
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: ' + str(i - 1)
        expected_rows.append([get_subnet('User'), get_ip(host), host_table, False, 'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Port Scan
    ip_address = IPv4Address(get_ip('User3'))
    action = DiscoverNetworkServices(ip_address=ip_address, agent=agent_name, session=0)
    results = cyborg.step(action=action, agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(1)  # TRUE
    assert observation.success == expected_success

    expected_rows = [
        [get_subnet('User'), get_ip('User0'), 'User0', False, 'Privileged'],
        [get_subnet('User'), get_ip('User3'), 'UNKNOWN_HOST: 2', True, 'None']
    ]
    for i in [1, 2, 4]:
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: ' + str(i - 1)
        expected_rows.append([get_subnet('User'), get_ip(host), host_table, False, 'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Remote Exploit
    ip_address = IPv4Address(get_ip('User3'))
    action = ExploitRemoteService(ip_address=ip_address, agent=agent_name, session=0)
    results = cyborg.step(action=action, agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(1)  # TRUE
    assert observation.success == expected_success

    expected_rows = [
        [get_subnet('User'), get_ip('User0'), 'User0', False, 'Privileged'],
        [get_subnet('User'), get_ip('User3'), 'User3', True, 'User']
    ]
    for i in [1, 2, 4]:
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: ' + str(i - 1)
        expected_rows.append([get_subnet('User'), get_ip(host), host_table, False, 'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()
    for i in range(7):
        cyborg.step() # extra steps to give blue time to react
    # Test Privilege Escalate
    action = PrivilegeEscalate(hostname='User3', agent=agent_name, session=0)
    results = cyborg.step(action=action, agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum.FALSE
    assert observation.success == expected_success

    expected_rows = [
        [get_subnet('User'), get_ip('User0'), 'User0', False, 'Privileged'],
        [get_subnet('User'), get_ip('User3'), 'User3', True, 'None']
    ]
    for i in [1, 2, 4]:
        host = 'User' + str(i)
        host_table = 'UNKNOWN_HOST: ' + str(i - 1)
        expected_rows.append([get_subnet('User'), get_ip(host), host_table, False, 'None'])

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Failed Action
    action = Impact(hostname='User0', agent=agent_name, session=0)
    results = cyborg.step(action=action, agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(3)  # FALSE
    assert observation.success == expected_success

    # Expected table same as previous
    assert observation.get_string() == expected_table.get_string()

def test_red_vector():
    path = str(inspect.getfile(CybORG))    
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'    
    
    cyborg = RedTableWrapper(env=CybORG(path, 'sim'), output_mode='vector')    
    agent_name = 'Red'
    results = cyborg.reset(agent=agent_name)
    observation = results.observation

    expected_vector = np.array([ -1,  0,  0,  1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1])
    assert all(observation == expected_vector)

@pytest.fixture(params=['table','raw'])
def cyborg(request,agents = {'Blue':BlueMonitorAgent,'Red':B_lineAgent},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = RedTableWrapper(env=CybORG(path, 'sim', agents=agents),output_mode=request.param)
    cyborg.set_seed(seed)
    return cyborg

def test_get_attr(cyborg):
    for attribute in ['get_observation','get_action_space','get_last_action','get_ip_map',
            'get_rewards', 'get_agent_state']:
        assert cyborg.get_attr(attribute) == cyborg.env.get_attr(attribute)

def test_get_observation(cyborg):
    red_results = cyborg.reset(agent='Red')
    step_obs = red_results.observation
    method_obs = cyborg.get_observation('Red')
    if cyborg.output_mode == 'table':
        step_obs = step_obs.get_string()
        method_obs = method_obs.get_string()
    assert step_obs == method_obs

    blue_results = cyborg.reset(agent='Blue')
    step_obs = blue_results.observation
    method_obs = cyborg.get_observation('Blue')
    assert step_obs == method_obs

def test_get_agent_state(cyborg):
    cyborg.step()
    assert cyborg.get_agent_state('True') == cyborg.get_attr('get_agent_state')('True')
    assert cyborg.get_agent_state('Red') == cyborg.get_attr('get_agent_state')('Red')
    assert cyborg.get_agent_state('Blue') == cyborg.get_attr('get_agent_state')('Blue')

def test_get_action_space(cyborg):
    assert cyborg.get_action_space('Red') == cyborg.get_attr('get_action_space')('Red')
    assert cyborg.get_action_space('Blue') == cyborg.get_attr('get_action_space')('Blue')

def test_get_last_action(cyborg):
    cyborg.step()
    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')

def test_get_ip_map(cyborg):
    assert cyborg.get_ip_map() == cyborg.get_attr('get_ip_map')()

def test_get_rewards(cyborg):
    assert cyborg.get_rewards() == cyborg.get_attr('get_rewards')()
