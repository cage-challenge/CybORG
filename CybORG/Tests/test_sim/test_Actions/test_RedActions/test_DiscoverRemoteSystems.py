import pytest 
from .red_action_fixtures import cyborg, params, obs_failure, red_killchain, hostnames
import itertools 
from CybORG.Shared.Actions import DiscoverRemoteSystems

@pytest.mark.parametrize('parameter', ['subnet','session','agent'])
def test_DiscoverRemoteSystems_junk_input(cyborg,params,parameter):
    # Here we make sure the action handles junk inputs properly.
    subnet = cyborg.environment_controller.state.subnet_name_to_cidr['User']
    params['subnet'] = subnet
    params[parameter] = 'Junk'
    action = DiscoverRemoteSystems(**params)
    _ = cyborg.step(action=action,agent='Red')
    last_action = cyborg.get_last_action('Red')

    assert 'Invalid' in last_action.__class__.__name__

@pytest.mark.parametrize('subnet',['Enterprise','Operational'])             # Omit User subnet because it will succeed. 
def test_DiscoverRemoteSystems_initial_state(cyborg, params, obs_failure, subnet):
    # Here we test the actions out from the initial state.
    cidr = cyborg.environment_controller.state.subnet_name_to_cidr[subnet]
    action = DiscoverRemoteSystems(subnet=cidr,**params)
    results = cyborg.step(action=action,agent='Red')
    assert results.observation == obs_failure

@pytest.mark.parametrize('subnet',enumerate(['User','Enterprise','Operational']))
def test_DiscoverRemoteSystems_killchain(red_killchain, subnet):
    # Here we test the actions during the killchain.
    scans = [x[1] for x in red_killchain['history'] if x[0] == 'DiscoverRemoteSystems']
    obs = scans[subnet[0]]
    assert obs['success'] == True

    cidr = red_killchain['cyborg'].environment_controller.state.subnet_name_to_cidr[subnet[1]]
    all_ips = red_killchain['cyborg'].environment_controller.state.ip_addresses.keys()
    subnet_ips = [ip.compressed for ip in all_ips if ip in cidr]
    hostids = [ip for ip in obs.keys() if ip!='success']
    assert len(hostids) == len(subnet_ips)                                  # Check we got all the ips on the subnet

    hosts = [obs[d] for d in hostids]                                       # List of all host data from observation 
    assert all([list(h.keys()) == ['Interface'] for h in hosts])            # Check host data is only interfaces

    interfaces = itertools.chain(*[h['Interface'] for h in hosts])          # Iterator of all interfaces from observation
    assert [i['IP Address'].compressed for i in interfaces] == subnet_ips   # Check the gathered ips are correct
    assert all([i['Subnet'].compressed == cidr for i in interfaces])        # Check subnet is correct

@pytest.mark.parametrize('subnet',enumerate(['User','Enterprise','Operational']))
def test_DiscoverRemoteSystems_followup(red_killchain, params, subnet):
    # Here we test the actions after a full killchain has been performed.
    scans = [x[1] for x in red_killchain['history'] if x[0] == 'DiscoverRemoteSystems']
    expected_obs = scans[subnet[0]]

    cyborg = red_killchain['cyborg']
    cidr = cyborg.environment_controller.state.subnet_name_to_cidr[subnet[1]]
    action = DiscoverRemoteSystems(subnet=cidr,**params)
    results = cyborg.step(action=action,agent='Red')
    assert results.observation == expected_obs
