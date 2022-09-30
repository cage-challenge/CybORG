import pytest
import inspect
from ipaddress import IPv4Address, IPv4Network

from prettytable import PrettyTable

from CybORG import CybORG
from CybORG.Shared.Enums import TrinaryEnum
from CybORG.Agents.Wrappers.TrueTableWrapper import TrueTableWrapper
from CybORG.Shared.Actions.AbstractActions import DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, PrivilegeEscalate, Impact, Monitor
from CybORG.Agents import B_lineAgent


def get_table(rows):    
    table = PrettyTable([    
        'Subnet',    
        'IP Address',    
        'Hostname',    
        'Known',
        'Scanned',    
        'Access',    
        ])    
    for r in rows:
        table.add_row(rows[r])

    table.sortby = 'Hostname'
    return table    

@pytest.mark.skip
def test_TrueTableWrapper():
    path = str(inspect.getfile(CybORG))    
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'    
    
    cyborg = TrueTableWrapper(env=CybORG(path, 'sim'), observer_mode=False)
    agent_name = 'Red'

    def get_ip(host):
        ip_map = cyborg.env.environment_controller.state.ip_addresses
        for ip in ip_map:
            if ip_map[ip] == host:
                return str(ip)
        raise ValueError('Searched for host with no ip address. Probably invalid hostname.')

    def get_subnet(subnet):
        cidr_map = cyborg.env.environment_controller.state.subnet_name_to_cidr
        return str(cidr_map[subnet])

    def get_generic_rows():
        generic_rows = {}
        for i in range(5):
            host = 'User' + str(i)
            known = True if i==0 else False
            access = 'Privileged' if i == 0 else 'None'
            generic_rows[host] = [get_subnet('User'),get_ip(host),host,
                    known, False,access]
        for i in range(3):
            host = 'Enterprise' + str(i)
            generic_rows[host] = [get_subnet('Enterprise'),get_ip(host),host,
                    False, False,'None']
        for i in range(3):
            host = 'Op_Host' + str(i)
            generic_rows[host] = [get_subnet('Operational'),get_ip(host),host,
                    False, False,'None']

        host = 'Op_Server0'
        generic_rows[host] = [get_subnet('Operational'),get_ip(host),host,
                    False, False,'None']
        host = 'Defender'
        generic_rows[host] = [get_subnet('Enterprise'),get_ip(host),host,
                    False, False,'None']

        return generic_rows

    # Test Initial Observation
    results = cyborg.reset(agent=agent_name)    
    observation = results.observation

    expected_rows = get_generic_rows()
    expected_table = get_table(expected_rows)

    # We compare strings instead of tables. See comments in get_table function.
    assert observation.get_string() == expected_table.get_string()

    # Test New Host Discovery
    subnet = IPv4Network(get_subnet('User'))
    action = DiscoverRemoteSystems(subnet=subnet, agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(2) 
    assert observation.success == expected_success

    expected_rows = get_generic_rows()
    for i in range(1,5):
        host = 'User' + str(i)
        expected_rows[host][3] = True

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Port Scan
    ip_address = IPv4Address(get_ip('User4'))
    action = DiscoverNetworkServices(ip_address=ip_address, agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(2) 
    assert observation.success == expected_success

    expected_rows['User4'][4] = True

    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Remote Exploit
    ip_address = IPv4Address(get_ip('User4'))
    action = ExploitRemoteService(ip_address=ip_address, agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(2) 
    assert observation.success == expected_success

    expected_rows['User4'][-1] = 'User'
    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Privilege Escalate
    action = PrivilegeEscalate(hostname='User4', agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(2) 
    assert observation.success == expected_success

    expected_rows['User4'][-1] = 'Privileged'
    expected_rows['Enterprise0'][3] = True
    expected_table = get_table(expected_rows)
    assert observation.get_string() == expected_table.get_string()

    # Test Failed Action
    action = Impact(hostname='User0',agent=agent_name,session=0)
    results = cyborg.step(action=action,agent=agent_name)
    observation = results.observation

    expected_success = TrinaryEnum(2)
    assert observation.success == expected_success 

    # Expected table same as previous
    assert observation.get_string() == expected_table.get_string()

@pytest.fixture(params=[True,False])
def cyborg(request,agents = {'Red':B_lineAgent},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = TrueTableWrapper(CybORG(path, 'sim', agents=agents),observer_mode=request.param)
    cyborg.set_seed(seed)
    return cyborg

def test_get_attr(cyborg):
    for attribute in ['get_observation','get_action_space','get_last_action','get_ip_map',
            'get_rewards', 'get_agent_state']:
        assert cyborg.get_attr(attribute) == cyborg.env.get_attr(attribute)

def test_get_observation(cyborg):
    for i in range(10):
        cyborg.step(agent='Blue',action=Monitor(session=0,agent='Blue'))

        blue_obs = cyborg.get_observation('Blue')
        assert blue_obs == cyborg.get_attr('get_observation')('Blue')
        
        red_obs = cyborg.get_observation('Red')
        assert red_obs == cyborg.get_attr('get_observation')('Red')

def test_get_agent_state(cyborg):
    for i in range(10):
        true_table = cyborg.get_table()
        assert cyborg.get_agent_state('True').get_string() == true_table.get_string()

        assert cyborg.get_agent_state('Red') == cyborg.get_attr('get_agent_state')('Red')
        assert cyborg.get_agent_state('Blue') == cyborg.get_attr('get_agent_state')('Blue')

def test_get_action_space(cyborg):
    assert cyborg.get_action_space('Red') == cyborg.get_attr('get_action_space')('Red')
    assert cyborg.get_action_space('Blue') == cyborg.get_attr('get_action_space')('Blue')

def test_get_last_action(cyborg):
    cyborg.step(agent='Blue',action=Monitor(session=0,agent='Blue'))

    assert cyborg.get_last_action('Red') == cyborg.get_attr('get_last_action')('Red')
    assert cyborg.get_last_action('Blue') == cyborg.get_attr('get_last_action')('Blue')

def test_get_ip_map(cyborg):
    assert cyborg.get_ip_map() == cyborg.get_attr('get_ip_map')()

def test_get_rewards(cyborg):
    assert cyborg.get_rewards() == cyborg.get_attr('get_rewards')()

@pytest.mark.skip("Not Implemented Yet")
def test_true_obs_to_table():
    assert False
