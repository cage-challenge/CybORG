import pytest 
from deceptive_action_fixtures import cyborg, params, obs_failure, red_killchain, HOSTNAMES, blue_spam
import itertools 
from CybORG.Shared.Actions import DecoySvchost, ExploitRemoteService, BlueKeep
from CybORG.Shared.Enums import SessionType, OperatingSystemType, ProcessType, ProcessState
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort, LinuxEphemeralPort

invalid_hosts = ['User2','User3','User4','Enterprise0','Enterprise1','Enterprise2', \
        'Op_Server0', 'Op_Host0', 'Op_Host1','Op_Host2'] # Linux Hosts and those with Svchost: User 0 and User 1

@pytest.mark.parametrize('parameter', ['hostname','session','agent'])
def test_DecoySvchost_junk_input(params,parameter,cyborg):
    # Here we make sure the action handles junk inputs properly.
    params['hostname'] = 'User0'
    params[parameter] = 'Junk'
    action = DecoySvchost(**params)
    _ = cyborg.step(action=action,agent='Blue')
    last_action = cyborg.get_last_action('Blue')

    assert 'Invalid' in last_action.__class__.__name__

@pytest.mark.parametrize('host',HOSTNAMES)
def test_DecoySvchost_without_red(cyborg, params, obs_failure, host,blue_spam):
    # Here we test out the action without any red activity
    history = blue_spam(action=DecoySvchost, params=params,cyborg=cyborg)['history']
    obs = [x[1] for x in history if x[0] == host][0]
    if host in invalid_hosts:
        assert obs == obs_failure
        return

    assert obs['success'] == True
    assert sorted(obs.keys()) == sorted(['success',host])
    host_data = obs[host]
    assert [x for x in host_data.keys()] == ['Processes']
    assert len(host_data['Processes']) == 1
    connection = host_data['Processes'][0]
    assert sorted(connection.keys()) == sorted(['PID','PPID','Service Name', 'Username'])
    os_type = cyborg.environment_controller.state.hosts[host].os_type
    assert connection['PID'] == Win2008EphemeralPort() \
            if os_type == OperatingSystemType.WINDOWS else LinuxEphemeralPort()
    assert connection['PPID'] == 1
    assert connection['Service Name'] == 'svchost'
    assert connection['Username'] == 'ubuntu'

@pytest.mark.parametrize('host', HOSTNAMES)
def test_DecoySvchost_repeat(red_killchain, params, host, obs_failure,cyborg,blue_spam):
    # Here we test the actions work twice
    blue_actions = blue_spam(action=DecoySvchost, params=params,cyborg=cyborg)
    expected_obs = [x[1] for x in blue_actions['history'] if x[0] == host][0]
    cyborg = blue_actions['cyborg']
    action = DecoySvchost(hostname=host,**params)
    results = cyborg.step(action=action,agent='Blue')
    assert results.observation == obs_failure #expected_obs

@pytest.mark.parametrize('host',HOSTNAMES)
@pytest.mark.parametrize('exploit',[BlueKeep])
def test_DecoySvchost_killchain(blue_spam,host,cyborg,red_killchain, params, exploit):
    # Here we test the interactions between blue and red
    if host in invalid_hosts:
        return
    history = blue_spam(action=DecoySvchost, params=params,cyborg=cyborg)['history']
    expected_obs = [x[1] for x in history if x[0] == host][0]

    cyborg.reset(agent='Blue')
    action = DecoySvchost(hostname=host,**params)
    results = cyborg.step(action=action,agent='Blue')
    # TODO: Refactor this part to add more conditions
    assert results.observation[host]['Processes'][0]['Service Name'] == 'svchost'
     
    cyborg = red_killchain(cyborg,host)['cyborg']

    action = DecoySvchost(hostname=host,**params)
    results = cyborg.step(action=action,agent='Blue')
    assert results.observation['success'] == True

    ip = cyborg.get_ip_map()[host]
    action = exploit(ip_address=ip, agent='Red',session=0, target_session=0)
    results = cyborg.step(action=action, agent='Red')
    assert 'Invalid' not in cyborg.get_last_action('Red').__class__.__name__
    assert results.observation['success'] == False


    blue_obs = cyborg.get_observation('Blue')
    assert host in blue_obs
    assert 'Processes' in blue_obs[host]
    assert len(blue_obs[host]['Processes']) > 0

@pytest.mark.parametrize('host', HOSTNAMES)
def test_DecoySvchost_followup(red_killchain, params, host, cyborg,blue_spam, obs_failure):
    # Here we test the actions work after red has already compromised the system
    blue_actions = blue_spam(action=DecoySvchost, params=params,cyborg=cyborg)
    expected_obs = [x[1] for x in blue_actions['history'] if x[0] == host][0]


    cyborg = red_killchain(cyborg)['cyborg']
    action = DecoySvchost(hostname=host,**params)
    results = cyborg.step(action=action,agent='Blue')
    # TODO Refactor for better comparison
    obs = results.observation
    if host in invalid_hosts:
        assert obs == obs_failure
        return

    assert results.observation['success'] == True
    assert results.observation[host]['Processes'][0]['Service Name'] == 'svchost'
