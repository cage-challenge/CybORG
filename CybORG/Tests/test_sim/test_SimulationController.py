from time import sleep

import networkx as nx
import pytest
from matplotlib import pyplot as plt


@pytest.fixture()
def create_simulation_controller(create_cyborg_sim):
    cyborg = create_cyborg_sim
    ctrl = cyborg.environment_controller
    return ctrl


def test_reset(create_simulation_controller):
    # create CybORG with generic agents (controlled by code here), take several actions, then call reset, create new env
    # from same scenario, and check that they are exactly equal in state
    # Follow instantiation process from meeting diagram
    ctrl = create_simulation_controller

    # take several actions here

    ctrl.reset()
    ctrl2 = create_simulation_controller
    assert ctrl.get_agent_state('Red') == ctrl2.get_agent_state('Red')


def test_get_osint(create_simulation_controller):
    # what/how to test here - what osint rfi's are there?
    sim_controller = create_simulation_controller
    for obs in sim_controller.observation:
        assert obs is not None
    #assert "Blue" in sim_controller.observation
    assert "Red" in sim_controller.observation

# Test to display link diagram
# def test_link_diagram(create_cyborg_sim):
#     G = create_cyborg_sim.environment_controller.state.link_diagram
#     pos = nx.spring_layout(G, seed=225)  # Seed for reproducible layout
#     nx.draw(G, pos)
#     plt.show()
