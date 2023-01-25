import pytest
import inspect

from CybORG import CybORG
from CybORG.Agents import MonitorAgent
import inspect
import json
import time

import numpy as np
import pygame
from networkx import number_connected_components

from CybORG import CybORG
from CybORG.Agents import RandomAgent, DroneRedAgent, SleepAgent, RemoveBlueDrone, RetakeBlueDrone
from CybORG.Agents.SimpleAgents.DroneRedAgent import BlockAgent, FloodAgent, LegalExploitDrone
from CybORG.Agents.SimpleAgents.GreenDroneAgent import GreenDroneAgent
from CybORG.Agents.SimpleAgents.RedDroneWorm import RedDroneWormAgent
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.Actions.GreenActions.SendData import SendData
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator

def test_confidentiality():
    return 0

def test_integrity():
    return 0


def test_availability():
    return 0


def test_rules_agents():
    for red_agent in [SleepAgent, DroneRedAgent, FloodAgent, RandomAgent, LegalExploitDrone, RedDroneWormAgent]:
        for blue_agent in [SleepAgent, BlockAgent, RemoveBlueDrone, RetakeBlueDrone, RandomAgent]:
            sg = DroneSwarmScenarioGenerator(num_drones=18, starting_num_red=0,
                                             default_red_agent=red_agent,
                                             all_external=True, maximum_steps=500,
                                             max_length_data_links=25)
            cyborg = CybORG(sg, agents={f'blue_agent_{agent}': blue_agent(name=f'blue_agent_{agent}') for agent in
                                        range(sg.num_drones)}, seed=123)
            for j in range(3):
                for i in range(500):
                    # start_time = time.time()
                    blocks = dict(cyborg.environment_controller.state.blocks)
                    cyborg.step()
                    reward_distribution = cyborg.get_rewards()
                    blocked_green_actions = [a for a in cyborg.environment_controller.blocked_actions if type(a) is SendData]
                    green_actions = {agent: act for agent, act in cyborg.environment_controller.action.items() if
                                     type(act) is SendData}
                    compromised_comms = []
                    for agent, act in green_actions.items():
                        hostname = cyborg.environment_controller.state.sessions[act.agent][act.session].hostname
                        route = act.get_used_route(cyborg.environment_controller.state)
                        if route is not None and not act.dropped:
                            recorded = False
                            for other_hostname in route:
                                # Get host object for corresponding hostname
                                host = cyborg.environment_controller.state.hosts[other_hostname]
                                # Get the list of agents mapped to sessions for the host
                                host_agents = host.sessions.keys()
                                # Iterate through list of agents operating session
                                for a in host_agents:
                                    # Check that agent's team name contains 'red', assume modification if true
                                    if 'red' in a.lower():
                                        # Iterate through list of session objects under agent
                                        for session in cyborg.environment_controller.state.sessions[a].values():
                                            # Check if agent has escalated privileges within session
                                            if session.username == 'root' or session.username == 'SYSTEM':
                                                compromised_comms.append(act)
                                                recorded = True
                                                break
                                    if recorded:
                                        break
                                if recorded:
                                    break
                    assert len(compromised_comms) <= 18, f"{red_agent.__name__} {blue_agent.__name__}, {j} {i}"
                    for act in [act for act in cyborg.environment_controller.dropped_actions if type(act) is SendData]:
                        assert act.execute(cyborg.environment_controller.state).success == False
                    assert round(sum(reward_distribution['Blue'].values())) <= -(
                                len(set([act.agent for act in cyborg.environment_controller.dropped_actions if
                                     type(act) is SendData])) + len(
                            [act for act in cyborg.environment_controller.routeless_actions if type(act) is SendData])), \
                        f"{round(sum(reward_distribution['Blue'].values()))}, {len([act for act in cyborg.environment_controller.dropped_actions if type(act) is SendData])} {len([act for act in cyborg.environment_controller.routeless_actions if type(act) is SendData])} {red_agent.__name__} {blue_agent.__name__}, {j} {i}"

                    assert round(sum(reward_distribution['Blue'].values())) <= -(len(blocked_green_actions) + len(
                            [act for act in cyborg.environment_controller.routeless_actions if type(act) is SendData])), \
                        f"{round(sum(reward_distribution['Blue'].values()))}, {len(blocked_green_actions)} {len([act for act in cyborg.environment_controller.routeless_actions if type(act) is SendData])} {red_agent.__name__} {blue_agent.__name__}, {j} {i}"

                cyborg.reset()


def test_blue_reward_after_spawn():
    sg = DroneSwarmScenarioGenerator(num_drones=18, starting_num_red=0, red_internal_only=False, red_spawn_rate=1, default_red_agent=SleepAgent)
    cyborg = CybORG(scenario_generator=sg, seed=123)
    reward = cyborg.step('blue_agent_0').reward
    assert len([i for i in cyborg.active_agents if 'red' in i]) == 1
    print(reward)
    print([cyborg.get_last_action(agent) for agent in cyborg.environment_controller.agent_interfaces.keys() if 'green' in agent and type(cyborg.get_last_action(agent)) is SendData])
    assert reward > -len([agent for agent in cyborg.environment_controller.agent_interfaces.keys() if 'green' in agent and type(cyborg.get_last_action(agent)) is SendData])
    reward = cyborg.step('blue_agent_0').reward
    assert len([i for i in cyborg.active_agents if 'red' in i]) == 2
    print(reward)
    print([cyborg.get_last_action(agent) for agent in cyborg.environment_controller.agent_interfaces.keys() if 'green' in agent and type(cyborg.get_last_action(agent)) is SendData])
    assert reward > -len([agent for agent in cyborg.environment_controller.agent_interfaces.keys() if 'green' in agent and type(cyborg.get_last_action(agent)) is SendData])
