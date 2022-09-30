import pytest

from CybORG.Agents import HeuristicRed

killchain = ['DiscoverRemoteSystems', 'DiscoverNetworkServices', 'ExploitRemoteService','PrivilegeEscalate']

def check_results(results,step,cyborg_scenario1b):
    cyborg = cyborg_scenario1b
    name = results.action.__class__.__name__

    # Opening moves are predictable, should eventually find Op Server and perform Impact.
    # if step < 4:
    #     assert name == killchain[step]

    # elif step > 55:
    #     assert name == 'Impact'


def test_HeuristicRed(cyborg_scenario1b):
    cyborg = cyborg_scenario1b
    agent = HeuristicRed(np_random=cyborg.np_random)
    results = cyborg.reset(agent='Red')
    obs = results.observation
    history = []

    for step in range(60):
        action = agent.get_action(obs)
        results = cyborg.step(agent='Red',action=action)

        name = results.action.__class__.__name__

        obs = results.observation

        check_results(results,step,cyborg)
