import pytest
import inspect

from CybORG.Tests.test_sim.test_Acceptance.agent_fixtures import cyborg

from CybORG import CybORG
from CybORG.Agents import DebuggingAgent, BlueMonitorAgent
from CybORG.Shared.Actions import Restore

@pytest.fixture
def security_values():
    security_values = {
            'User0':(0,0),
            'User1':(-0.1,0),
            'User2':(-0.1,0),
            'User3':(0,-0.1),
            'User4':(0,-0.1),
            'Enterprise0':(0,-1),
            'Enterprise1':(0,-1),
            'Enterprise2':(0,-1),
            'Defender':(0,0),
            'Op_Server0':(0,-1),
            'Op_Host0':(0,-0.1),
            'Op_Host1':(0,-0.1),
            'Op_Host2':(0,-0.1),
            }
    return security_values

@pytest.fixture
def availability_values():
    availability_values = {
            'User0':0,
            'User1':0,
            'User2':0,
            'User3':0,
            'User4':0,
            'Enterprise0':-1,
            'Enterprise1':-1,
            'Enterprise2':-1,
            'Defender':0,
            'Op_Server0':-10,
            'Op_Host0':-0.1,
            'Op_Host1':-0.1,
            'Op_Host2':-0.1,
            }
    return availability_values

@pytest.mark.skip()
def check_results_security(results,step,cyborg,target,security_values,previous_reward):
    name = results.action.__class__.__name__
    blue_reward = cyborg.get_rewards()['Blue']
    
    if name == 'ExploitRemoteService':
        expected_reward = security_values[target][0]
    elif name == 'PrivilegeEscalate':
        expected_reward = security_values[target][1]
    else:
        expected_reward = 0

    assert round(blue_reward - previous_reward,1) == expected_reward


@pytest.mark.skip()
def test_security_reward(cyborg,security_values):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    hostnames = ['User0','User1','User2','User3','User4','Enterprise0','Enterprise1',
            'Enterprise2','Defender','Op_Server0','Op_Host0','Op_Host1','Op_Host2']

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    previous_reward = 0
    for step in range(41):
        action = agent.get_action(obs)

        results = cyborg.step(agent='Red',action=action)

        obs = results.observation

        history.append((action,results.reward))
        target = hostnames[agent.position]

        check_results_security(results,step,cyborg,target,security_values,previous_reward)
        blue_reward = cyborg.get_rewards()['Blue']
        previous_reward = blue_reward

@pytest.mark.skip()
def test_security_reward_repeat(cyborg,security_values):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    hostnames = ['User0','User1','User2','User3','User4','Enterprise0','Enterprise1','Enterprise2',
            'Defender','Op_Server0','Op_Host0','Op_Host1','Op_Host2']

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    # Initial pass through the network
    previous_reward = 0
    for step in range(41):
        action = agent.get_action(obs)

        results = cyborg.step(agent='Red',action=action)

        obs = results.observation

        history.append((action,results.reward))
        target = hostnames[agent.position]

        blue_reward = cyborg.get_rewards()['Blue']
        previous_reward = blue_reward

    # Resetting agent to go through network again
    agent.position = 0
    for ip in agent.ip_status:
        hostname = agent.ip_map[ip]
        agent.ip_status[ip] = 1 if hostname != 'Op_Host2' else 0
        if hostname == 'User0':
            agent.active_ip = ip

    # Checking additional exploits produce nothing
    for step in range(30):
        action = agent.get_action(obs)

        results = cyborg.step(agent='Red',action=action)

        obs = results.observation

        history.append((action,results.reward))
        target = hostnames[agent.position]

        blue_reward = cyborg.get_rewards()['Blue']
        assert blue_reward == previous_reward

@pytest.mark.skip()
def test_availability_reward_impact(cyborg,availability_values):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    hostnames = ['User3','Enterprise0','Enterprise2','Op_Server0']

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    previous_reward = 0
    for step in range(24):
        action = agent.get_action(obs)

        results = cyborg.step(agent='Red',action=action)

        obs = results.observation

        history.append((action,results.reward))
        target = hostnames[agent.position]

        blue_reward = cyborg.get_rewards()['Blue']
        if action.__class__.__name__ == 'Impact':
            assert round(blue_reward - previous_reward,1) == availability_values['Op_Server0']
        else:
            previous_reward = blue_reward


@pytest.mark.skip()
def test_availability_reward_restore_solo(cyborg,availability_values):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    hostnames = ['User0','User1','User2','User3','User4','Enterprise0','Enterprise1',
            'Enterprise2','Defender','Op_Server0','Op_Host0','Op_Host1','Op_Host2']

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    for host in hostnames:
        action = Restore(session=0,agent='Blue',hostname=host)

        results = cyborg.step(agent='Blue',action=action)

        history.append((action,results.reward))
        target = hostnames[agent.position]

        assert results.reward == -1

@pytest.mark.skip()
def test_availability_reward_restore(cyborg,availability_values,security_values):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    hostnames = ['User0','User1','User2','User3','User4','Enterprise0','Enterprise1',
            'Enterprise2','Defender','Op_Server0','Op_Host0','Op_Host1','Op_Host2']

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    # Pollute hosts with red's presence
    previous_reward = 0
    for step in range(60):
        action = agent.get_action(obs)

        results = cyborg.step(agent='Red',action=action)

        obs = results.observation

        history.append((action,results.reward))
        target = hostnames[agent.position]
        blue_reward = cyborg.get_rewards()['Blue']
        previous_reward = blue_reward

    # Clean up the mess and check reward is correct
    for host in hostnames:
        action = Restore(session=0,agent='Blue',hostname=host)

        results = cyborg.step(agent='Blue',action=action)

        history.append((action,results.reward))

        assert results.reward == round(previous_reward - sum(security_values[host]) -1,2)
        previous_reward = results.reward + 1

