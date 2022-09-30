import inspect

import pytest

from CybORG import CybORG
from CybORG.Agents import DebuggingAgent
from CybORG.Shared.Enums import TrinaryEnum

HOSTNAMES = ['User0', 'User1', 'User2', 'User3', 'User4','Enterprise0','Enterprise1','Enterprise2',
            'Op_Server0','Op_Host0','Op_Host1','Op_Host2']

@pytest.fixture
def cyborg(agents = {},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
    cyborg = CybORG(path, 'sim', agents=agents)
    cyborg.set_seed(seed)
    return cyborg

@pytest.fixture
def params():
    return {'session':0,'agent':'Blue'}

@pytest.fixture
def obs_failure():
    return {'success': TrinaryEnum.FALSE}

def blue_spam_function(action,cyborg,params,hostnames=HOSTNAMES):
    results = cyborg.reset(agent='Blue')

    history = []
    for host in hostnames:
        action_instance = action(hostname=host,**params)
        results = cyborg.step(agent='Blue',action=action_instance)

        obs = results.observation
        history.append((host,obs))

    return {'history':history,'cyborg':cyborg}

@pytest.fixture
def blue_spam():
    return blue_spam_function

@pytest.fixture
def red_killchain():
    return red_killchain_function

def red_killchain_function(cyborg,host=None):
    obs = cyborg.reset('Red').observation

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in HOSTNAMES]
    agent = DebuggingAgent(ip_list=ip_list)

    history = []
    for i in range(40):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__
        obs = results.observation
        history.append((name,obs))

        if 'Services' in name:
            host_index = list(ip_map.values()).index(results.action.ip_address)
            hostname = list(ip_map.keys())[host_index]
            if hostname == host:
                break

    return {'history':history,'cyborg':cyborg}


