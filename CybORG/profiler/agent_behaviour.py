import inspect
import json
import time

import numpy as np
import pygame
from networkx import number_connected_components

from CybORG import CybORG
from CybORG.Agents import RandomAgent, DroneRedAgent, SleepAgent, RemoveBlueDrone, RetakeBlueDrone
from CybORG.Agents.SimpleAgents.DroneBlueAgent import AdvancedRetakeBlueDrone, AdvancedBlockBlueDrone
from CybORG.Agents.SimpleAgents.DroneRedAgent import BlockAgent, FloodAgent, LegalExploitDrone
from CybORG.Agents.SimpleAgents.GreenDroneAgent import GreenDroneAgent
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.Actions.GreenActions.SendData import SendData
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator


def get_agent_behaviour_metrics(number_of_drones=20, maximum_steps=100, number_of_repeats=100,
                                blue_agent_class=SleepAgent, red_agent_class=DroneRedAgent, max_length_data_links=25):
    sg = DroneSwarmScenarioGenerator(num_drones=number_of_drones, starting_num_red=0, default_red_agent=red_agent_class,
                                     all_external=True, maximum_steps=maximum_steps, max_length_data_links=max_length_data_links,
                                     red_spawn_rate=0.1)
    cyborg = CybORG(sg, agents={f'blue_agent_{agent}': blue_agent_class(name=f'blue_agent_{agent}') for agent in range(sg.num_drones)}, seed=123)
    data = []
    # clock = pygame.time.Clock()
    for j in range(number_of_repeats):
        cumm_rew = 0
        bandwidth_usage = []
        for i in range(maximum_steps):
            # start_time = time.time()
            cyborg.step()
            # end_time = time.time()
            # cyborg.render()
            # clock.tick(15)

            # agents = cyborg.active_agents
            # actions = {a: str(cyborg.get_last_action(a)) for a in cyborg.agents}
            # action_success = {a: cyborg.get_observation(a)['success'].name for a in cyborg.agents}
            reward_distribution = cyborg.get_rewards()
            bandwidth_usage = cyborg.environment_controller.bandwidth_usage.values()
            # dropped_actions = len(cyborg.environment_controller.dropped_actions)
            # routeless_actions = len(cyborg.environment_controller.routeless_actions)
            cumm_rew += sum(reward_distribution['Blue'].values())
            # get and log network properties
            # get connections per drone
            # connections = {host.hostname: len(interface.data_links) for host in cyborg.environment_controller.state.hosts.values() for
            #                interface in host.interfaces if interface.swarm}
            # get all routes
            # hosts = list(cyborg.environment_controller.state.hosts.keys())
            # max_route_length = 0
            # for index, host in enumerate(hosts):
            #     for other_host in hosts[index+1:]:
            #         route = RemoteAction.get_route(cyborg.environment_controller.state, other_host, host)
            #         if route is not None:
            #             max_route_length = max(len(route), max_route_length)
            num_components= number_connected_components(cyborg.environment_controller.state.link_diagram)
            # step_time = end_time - start_time
            # for host in connections:
            #     data.append({'bandwidth_usage': bandwidth_usage.get(host, 0),
            #                  'connections': connections[host],
            #                  'number_of_drones': n_drones,
            #                  'step_number': i,
            #                  'iteration': j,
            #                  'red_agent': str(red_agent.__name__),
            #                  'blue_agent': str(blue_agent.__name__)
            #                  })
            # data.append({'action_success': action_success,
            #              'actions': actions,
            #              'dropped_actions': dropped_actions,
            #              'routeless_actions': routeless_actions,
            #              'reward': sum(reward_distribution['Blue'].values()),
            #              'cummulative_reward': cumm_rew,
            #              'step_time': step_time,
            #              'max_route_length': max_route_length,
            #              'num_components': num_components,
            #              'blue_agents': len([1 for agent in agents if 'blue' in agent]),
            #              'number_of_drones': n_drones,
            #              'step_number': i,
            #              'iteration': j,
            #              'red_agent': str(red_agent.__name__),
            #              'blue_agent': str(blue_agent.__name__)})
            blocked_green_actions = []
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
                        for agent in host_agents:
                            # Check that agent's team name contains 'red', assume modification if true
                            if 'red' in agent.lower():
                                # Iterate through list of session objects under agent
                                for session in cyborg.environment_controller.state.sessions[agent].values():
                                    # Check if agent has escalated privileges within session
                                    if session.username == 'root' or session.username == 'SYSTEM':
                                        compromised_comms.append(act)
                                        recorded = True
                                        break
                            if recorded:
                                break
                        if recorded:
                            break
                        if other_hostname != hostname:
                            if other_hostname in cyborg.environment_controller.state.blocks and hostname in cyborg.environment_controller.state.blocks[other_hostname]:
                                blocked_green_actions.append(act)
                                break

            data.append({'dropped_green_actions': len([act for act in cyborg.environment_controller.dropped_actions if type(act) is SendData]),
                         'blocked_green_actions': len(blocked_green_actions),
                         'compromised_comms': len(compromised_comms),
                         'routeless_green_actions': len([act for act in cyborg.environment_controller.routeless_actions if type(act) is SendData]),
                         'iteration': j,
                         'num_components': num_components,
                         'red_agent': str(red_agent.__name__),
                         'blue_agent': str(blue_agent.__name__)})
            for b in bandwidth_usage:
                data.append({'bandwidth_usage': b,
                         'iteration': j,
                         'red_agent': str(red_agent.__name__),
                             'blue_agent': str(blue_agent.__name__)})
            if cyborg.environment_controller.done:
                data.append({'cummulative_reward': cumm_rew,
                             'game_length': i,
                             'iteration': j,
                             'red_agent': str(red_agent.__name__),
                             'blue_agent': str(blue_agent.__name__)})
                break
        cyborg.reset(seed=123+j)
    # return (number of successful actions per agent, bandwidth usage per drone, reward distribution)
    return data

if __name__ == "__main__":
    number_of_repeats = 10
    maximum_steps = 500
    max_length_data_links = 30
    n_drones = 18
    data = []
    for red_agent in [SleepAgent, DroneRedAgent, FloodAgent, LegalExploitDrone]:
    # for red_agent in [SleepAgent]:
    # for red_agent in [LegalExploitDrone]:
        for blue_agent in [SleepAgent, BlockAgent, RemoveBlueDrone, RetakeBlueDrone, AdvancedRetakeBlueDrone, AdvancedBlockBlueDrone]:
        # for blue_agent in [SleepAgent]:
        # for blue_agent in [AdvancedRetakeBlueDrone, AdvancedBlockBlueDrone]:
            print(f"Red: {red_agent.__name__}, Blue: {blue_agent.__name__}")
            d = get_agent_behaviour_metrics(number_of_drones=n_drones, number_of_repeats=number_of_repeats,
                                              red_agent_class=red_agent, blue_agent_class=blue_agent,
                                              maximum_steps=maximum_steps, max_length_data_links=max_length_data_links)
            data += d
    with open('agent_behaviour.data', 'w') as f:
        json_obj = json.dumps(data)
        f.write(json_obj)
