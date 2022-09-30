import inspect
import time

import numpy as np
# import plotly.express as px
from gym import Env, spaces
from pettingzoo import AECEnv, ParallelEnv

from CybORG import CybORG
from CybORG.Agents.Wrappers import OpenAIGymWrapper, ChallengeWrapper, FixedFlatWrapper, EnumActionWrapper
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator


def fps_calculator_open_ai_gym(env: Env, max_frames: int = 10000):
    num_resets = 0
    env.reset()
    start_time = time.time()
    for i in range(max_frames):
        observation, reward, done, info = env.step(env.action_space.sample())
        if done:
            num_resets += 1
            env.reset()
    end_time = time.time()
    # print(f'Time taken: {end_time-start_time} seconds for {max_frames} steps and {num_resets} resets')
    # print(f'{round(max_frames/(end_time-start_time), 2)} fps')


def fps_calculator_single_petting_zoo(env: AECEnv, max_frames: int = 10000):
    num_resets = 0
    env.reset()
    i = 0
    start_time = time.time()
    for agent in env.agent_iter():
        env.step(env.action_space(agent).sample())
        observation, reward, done, info = env.last()
        if done:
            num_resets += 1
            env.reset()
        i += 1
        if i > max_frames:
            break
    end_time = time.time()
    print(f'Time taken: {end_time - start_time} seconds for {max_frames} steps and {num_resets} resets')
    print(f'{round(max_frames / (end_time - start_time), 2)} fps')


def fps_calculator_parallel_petting_zoo(env: ParallelEnv, max_frames: int = 10000, verbose = False):
    num_resets = 0
    env.reset()
    action_space = spaces.Dict({agent: env.action_space(agent) for agent in env.possible_agents})
    max_frames = round(max_frames/len(action_space))
    start_time = time.time()
    for i in range(max_frames):
        observation, reward, done, info = env.step(action_space.sample())
        if list(done.values())[0]:
            num_resets += 1
            env.reset()
    end_time = time.time()
    if verbose:
        print(f'Time taken: {end_time - start_time} seconds for {max_frames*len(action_space)} steps and {num_resets} resets')
        print(f'{round(max_frames*len(action_space) / (end_time - start_time), 2)} fps')
    return max_frames*len(action_space) / (end_time - start_time)

def calculate_fps(number_of_drones, maximum_steps=100, number_of_repeats=100):
    sg = DroneSwarmScenarioGenerator(num_drones=number_of_drones, starting_num_red=0)
    cyborg = CybORG(sg)
    start_time = time.time()
    total_steps = 0
    i = 0
    for j in range(number_of_repeats):
        for i in range(maximum_steps):
            cyborg.step()
            if cyborg.environment_controller.done:
                total_steps += i
                break
        cyborg.reset()
    end_time = time.time()
    total_time = end_time-start_time
    fps = total_steps/total_time
    return fps

if __name__ == "__main__":
    import plotly.express as px
    # for param in ['Scenario1', 'Scenario1b']:
    #     print(param)
    #     path = str(inspect.getfile(CybORG))
    #     path = path[:-7] + f'/Shared/Scenarios/{param}.yaml'
    #     cyborg = CybORG(path, 'sim')
    #     fps_calculator_open_ai_gym(OpenAIGymWrapper('Red', FixedFlatWrapper(EnumActionWrapper(cyborg))))
    fps = np.zeros(50)
    for i in range(2,52):
        fps[i-2] = calculate_fps(i)
        print(f"{i}, {fps[i-2]}")
    with open('fps.data', 'w') as f:
        f.write(fps)
    fig = px.scatter(x=list(range(2,500)), y=fps, log_y=False, labels={"x": "Number of Drones", "y": "Steps per Second", })
    fig.show()

