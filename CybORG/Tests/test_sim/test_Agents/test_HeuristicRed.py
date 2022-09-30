import pytest

from agent_fixtures import cyborg

from CybORG.Agents import HeuristicRed

agent = HeuristicRed()
killchain = ['DiscoverRemoteSystems', 'DiscoverNetworkServices', 'ExploitRemoteService','PrivilegeEscalate']

def check_results(results,step,cyborg):
    name = results.action.__class__.__name__

    # Heuristic Agent should not fail unless trying to exploit defender
    if not results.observation['success'] :
        assert name == 'ExploitRemoteService'
        assert action.ip_address == cyborg.get_ip_map['Defender']

    # Opening moves are predictable, should eventually find Op Server and perform Impact.
    if step < 4:
        assert name == killchain[step]

    elif step > 55:
        assert name == 'Impact'

def test_HeuristicRed(cyborg):
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    for step in range(60):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__

        obs = results.observation
        

        check_results(results,step,cyborg)

