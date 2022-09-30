# This is an example on how to use the Renderer class.
import inspect
from time import sleep

from CybORG import CybORG
from CybORG.Agents import B_lineAgent, BlueReactRestoreAgent, BlueReactRemoveAgent, SleepAgent, DroneRedAgent, \
    RandomAgent, BaseAgent, RedMeanderAgent
from CybORG.Simulator.Scenarios import FileReaderScenarioGenerator, DroneSwarmScenarioGenerator
import pygame
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.RetakeControl import RetakeControl
import random



def run_episode_cc2(cyborg, agent):
    cyborg.reset()
    a = ''
    for i in range(100):
        # print(cyborg.environment_controller.get_last_action('Red'))
        stop = cyborg.render()
        action_space = cyborg.get_action_space('Blue')
        obs = cyborg.get_observation('Blue')
        if stop:
            break
        action = agent.get_action(obs, action_space)
        cyborg.step('Blue', action)
        # a = input(f'Step {i}, use q to quit, use n to go to next demo')
        if 'q' in a:
            quit()
        if 'n' in a:
            break

if __name__ == "__main__":

    # input('start? ')
    # CC2
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario2.yaml'
    sg = FileReaderScenarioGenerator(path)
    red_agent = RedMeanderAgent()
    cyborg = CybORG(sg, 'sim', agents={'Red': red_agent})
    # a = ''
    # for i in range(100):
    #     # print(cyborg.environment_controller.get_last_action('Red'))
    #     stop = cyborg.render()
    #     if stop:
    #         break
    #     cyborg.step()
    #     a = input(f'Step {i}, use q to quit, use n to go to next demo')
    #     if 'q' in a:
    #         quit()
    #     if 'n' in a:
    #         break
    # input('demo react remove')
    agent = BlueReactRemoveAgent()
    run_episode_cc2(cyborg, agent)
    # input('demo react restore')
    agent = BlueReactRestoreAgent()
    run_episode_cc2(cyborg, agent)
    #
    # CC3
    # input('')
    num_drones=20
    sg = DroneSwarmScenarioGenerator(num_drones=num_drones, max_length_data_links=25, red_spawn_rate=0, starting_num_red=0)
    cyborg = CybORG(sg, 'sim')
    cyborg.render()
    input('start2?')
    # Using pygame's clock to control the frame rate of the render
    clock = pygame.time.Clock()
    frame_rate = 15
    for i in range(50):
        for i in range(500):
            # print(cyborg.environment_controller.get_last_action('Red'))
            stop = cyborg.render()
            if stop:
                break
            cyborg.step()
            # for agent in cyborg.active_agents:
            #     if 'red' in agent:
            #         print(agent, cyborg.get_last_action(agent))
            # sleep(0.1)
            # a = input(f'Step {i}, use q to quit, use n to go to next demo')
            # if 'q' in a:
            #     quit()
            # if 'n' in a:
            #     break
            # sleep(0.5)
            clock.tick(frame_rate)
        cyborg.reset()
    # a = input('red drone agent')
    a = ''
    if 'q' in a:
        quit()

    # sg = DroneSwarmScenarioGenerator(max_length_data_links=25, num_drones=num_drones, red_spawn_rate=0, starting_num_red=1)
    # cyborg = CybORG(sg, 'sim')
    # for i in range(500):
    #     stop = cyborg.render()
    #     actions = {}
    #     if stop:
    #         quit()
    #     cyborg.parallel_step({})
    #     clock.tick(frame_rate)
    #     if cyborg.environment_controller.done:
    #         break
    #
    #     # a = input(f'Step {i}, use q to quit')
    #     if 'q' in a:
    #         quit()
    #     elif 'n' in a:
    #         break
    #
    # sg = DroneSwarmScenarioGenerator(max_length_data_links=25, num_drones=num_drones, red_spawn_rate=0, starting_num_red=1)
    # cyborg = CybORG(sg, 'sim')
    # for i in range(500):
    #     stop = cyborg.render()
    #     actions = {}
    #
    #     if stop:
    #         quit()
    #     agent_list = ['drone_0','drone_1', 'drone_2', 'drone_3','drone_4','drone_5', 'drone_6', 'drone_7','drone_8','drone_9', 'drone_10', 'drone_11', 'drone_12', 'drone_13', 'drone_14']
    #
    #     for agent in cyborg.active_agents:
    #         if 'blue' in agent:
    #             actions[agent] = RemoveOtherSessions(agent=agent, session=0)
    #
    #     cyborg.parallel_step(actions)
    #     clock.tick(frame_rate)
    #
    #     # a = input(f'Step {i}, use q to quit')
    #     if 'q' in a:
    #         quit()
    #     elif 'n' in a:
    #         break
    #
    # sg = DroneSwarmScenarioGenerator(max_length_data_links=25, num_drones=num_drones, red_spawn_rate=0, starting_num_red=1)
    # cyborg = CybORG(sg, 'sim')
    # for i in range(500):
    #     stop = cyborg.render()
    #     actions = {}
    #
    #     if stop:
    #         quit()
    #     agent_list = ['drone_0','drone_1', 'drone_2', 'drone_3','drone_4','drone_5', 'drone_6', 'drone_7','drone_8','drone_9', 'drone_10', 'drone_11', 'drone_12', 'drone_13', 'drone_14']
    #
    #     for agent in cyborg.active_agents:
    #         if 'blue' in agent:
    #             actions[agent] = RetakeControl(agent=agent, session=0, ip_address=cyborg.get_ip_map()[random.choice(agent_list)])
    #
    #     cyborg.parallel_step(actions)
    #     clock.tick(frame_rate)
    #
    #     # a = input(f'Step {i}, use q to quit')
    #     if 'q' in a:
    #         quit()
    #     elif 'n' in a:
    #         break
