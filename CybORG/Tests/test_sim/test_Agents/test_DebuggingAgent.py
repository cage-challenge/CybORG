import pytest

from agent_fixtures import cyborg

from CybORG.Agents import DebuggingAgent

killchain = ['DiscoverRemoteSystems','DiscoverNetworkServices', 'ExploitRemoteService','PrivilegeEscalate']

def check_results(results,step,cyborg,agent,duration,target):
    name = results.action.__class__.__name__
    assert results.observation['success']  != False  if target != 'Defender' else True # Double negative needed 
                                                                                 # because of UNKNOWN success value
    if step < 7:
        position = ((step-1) % 3) + 1 if step > 0 else 0
        assert name == killchain[position]
    elif step > duration-3:
        assert name == 'Impact'

def run_agent(cyborg,hostnames,duration):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    for step in range(duration):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__
        obs = results.observation
        history.append(action)
       
        target = hostnames[agent.position]

        check_results(results,step,cyborg,agent,duration,target)

def test_short_killchain(cyborg):
    hostnames = ['User2', 'Enterprise1','Enterprise2','Op_Server0']
    run_agent(cyborg,hostnames,24)

@pytest.mark.skip()
def test_long_killchain(cyborg):
    hostnames = ['User0','User1','User2','User3','User4','Enterprise0','Enterprise1','Enterprise2',
            'Defender','Op_Server0','Op_Host0','Op_Host1','Op_Host2','Op_Server0']
    run_agent(cyborg,hostnames,64)


def test_repeat_action(cyborg):
    hostnames = ['User0','User3','Enterprise0','Enterprise2','Op_Server0']
    
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    for step in range(24):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__
        obs = results.observation
        history.append(action)
       
        target = hostnames[agent.position]

    agent.position = 0
    for ip in agent.ip_status:
        hostname = agent.ip_map[ip]
        agent.ip_status[ip] = 1 if hostname != 'Op_Server0' else 0
        if hostname == 'User0':
            agent.active_ip = ip

    for step in range(2*len(hostnames)):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__
        obs = results.observation
        history.append(action)
       
        target = hostnames[agent.position]

        name = results.action.__class__.__name__
        assert name == ('ExploitRemoteService' if step % 2 == 0 \
            else 'PrivilegeEscalate')
