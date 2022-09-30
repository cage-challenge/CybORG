import inspect

import pytest

from CybORG import CybORG
from CybORG.Shared.Actions import *
from CybORG.Agents import RedMeanderAgent
from CybORG.Agents.Wrappers import BlueTableWrapper


hosts = [
        'User0',
        'User1',
        'User2',
        'User3',
        'User4',
        'Enterprise0',
        'Enterprise1',
        'Enterprise2',
        'Defender',
        'Op_Server0',
        'Op_Host0',
        'Op_Host1',
        'Op_Host2',
        ]

actions = [
        DecoyApache,
        DecoyFemitter,
        DecoyHarakaSMPT,
        DecoySmss,
        DecoySSHD,
        DecoySvchost,
        DecoySmss,
        DecoyTomcat,
        ]

@pytest.fixture
def cyborg():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
    return BlueTableWrapper(env=CybORG(path, 'sim'), output_mode='raw')

@pytest.fixture(params=hosts)
def host(request):
    return request.param

@pytest.fixture(params=actions)
def action(request, host):
    return request.param(hostname=host, agent='Blue', session=0)

def test_deception_appearance(cyborg, action):
    cyborg.reset()
    results = cyborg.step(action=action, agent='Blue')
    table = cyborg.get_table()
    anomalies = [v[3] for v in table._rows if v[3] != 'None']

    assert len(anomalies) == 0

@pytest.fixture
def cyborg_with_agent():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
    cyborg = CybORG(path, 'sim', agents={'Red':RedMeanderAgent})

    return BlueTableWrapper(env=cyborg, output_mode='table')

def test_scan_deception_combo(cyborg_with_agent, action):
    env = cyborg_with_agent
    env.reset()
    for i in range(50):
        results = env.step(action=action, agent='Blue')
        red_action = env.get_last_action('Red')
        if red_action.__class__.__name__ == 'DiscoverNetworkServices':
            table = results.observation
            anomalies = [v[3] for v in table._rows if v[3] != 'None']

            assert len(anomalies) == 1
    

