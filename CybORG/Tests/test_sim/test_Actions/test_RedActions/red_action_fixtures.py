import inspect

import pytest

from CybORG import CybORG
from CybORG.Agents import DebuggingAgent
from CybORG.Shared.Enums import TrinaryEnum


@pytest.fixture
def cyborg(agents = {},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
    cyborg = CybORG(path, 'sim', agents=agents)
    cyborg.set_seed(seed)
    return cyborg

@pytest.fixture
def params():
    return {'session':0,'agent':'Red'}

@pytest.fixture
def obs_failure():
    return {'success': TrinaryEnum.FALSE}

@pytest.fixture
def hostnames():
    return ['User0', 'User1', 'User2', 'User3', 'User4','Enterprise0','Enterprise1','Enterprise2',
            'Op_Server0','Op_Host0','Op_Host1','Op_Host2']

@pytest.fixture
def red_killchain(cyborg,hostnames):
    results = cyborg.reset(agent='Red')
    obs = results.observation

    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    history = []
    for i in range(39):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__
        obs = results.observation
        history.append((name,obs))

    return {'history':history,'cyborg':cyborg}


