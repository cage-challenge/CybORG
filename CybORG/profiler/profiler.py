import cProfile
import inspect

from gym.utils.seeding import np_random

# for visualisation of code profile:
# python -m cProfile -o profile.pstats profiler.py
# gprof2dot -f pstats profile.pstats | dot -Tpng -o output.png && eog output.png
# or with snakeviz
# snakeviz profile.pstats
from CybORG import CybORG
from CybORG.Agents import RandomAgent
from CybORG.Simulator.Scenarios.DroneSwarmScenarioGenerator import DroneSwarmScenarioGenerator
from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator


def run(path):
    aws = False
    # sg = FileReaderScenarioGenerator(path)
    sg = DroneSwarmScenarioGenerator(num_drones=20)
    np_rand, seed = np_random(123)
    def assign_agents(agent_list):
        return {agent: RandomAgent() for agent in agent_list}
    c = CybORG(scenario_generator=sg, agents=assign_agents(sg.create_scenario(np_rand).agents.keys()))
    try:
        for i in range(100):
            for j in range(1000):
                c.step()
                if c.environment_controller.done:
                    break
            c.reset()
    finally:
        c.shutdown(teardown=True)


path = str(inspect.getfile(CybORG))
path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
# cProfile.run("run()", sort='cumtime')
run(path)
