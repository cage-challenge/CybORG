import inspect
import pytest
from CybORG import CybORG

from agent_fixtures import cyborg

from CybORG.Agents import DebuggingAgent, B_lineAgent
from CybORG.Shared.Actions import Restore, ExploitRemoteService


def test_operational_nacl(cyborg):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    hostnames = ['User2','Enterprise1','Enterprise2','Op_Server0']
    ip_map = cyborg.get_ip_map()
    ip_list = [ip_map[h] for h in hostnames]
    agent = DebuggingAgent(ip_list=ip_list)

    for step in range(24):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__
        obs = results.observation
        history.append(action)
        
    # Restore Op Server and test red cannot impact
    action = Restore(session=0,agent='Blue',hostname='Op_Server0')
    results = cyborg.step(agent='Blue',action=action)

    action = agent.get_action(obs)
    results = cyborg.step(agent='Red',action=action)
    assert results.observation['success'] == False

    
    # Restore Enterprise subnet and test if red can exploit Op Server
    for hostname in ['Enterprise0','Enterprise1','Enterprise2']:
        action = Restore(session=0,agent='Blue',hostname=hostname)
        results = cyborg.step(agent='Blue',action=action)
        action = cyborg.get_last_action('Red')
        history.append((action,hostname))

    ip = ip_map['Op_Server0']
    action = ExploitRemoteService(agent='Red',session=0,ip_address=ip)
    results = cyborg.step(agent='Red',action=action)
    assert results.observation['success'] == False


@pytest.fixture
def cyborg_2(agents = {'Red':B_lineAgent},seed = 1):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim', agents=agents)
    cyborg.set_seed(seed)
    return cyborg

def test_operational_nacl_aug20_bug(cyborg_2):
    cyborg_2.reset()
    history = []

    for step in range(24):
        history = []
        cyborg_2.step()
        
    for host in ['Enterpris0','Enterprise1','Enterprise2','Op_Server0']:
        action = Restore(session=0,agent='Blue',hostname=host)
        cyborg_2.step(action=action,agent='Blue')
        assert cyborg_2.get_last_action('Red').__class__.__name__ == 'Impact'

    cyborg_2.step()
    assert cyborg_2.get_observation('Red')['success'] == False
    assert cyborg_2.get_rewards()['Blue'] > -10

