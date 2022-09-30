import cProfile
import inspect

from CybORG import CybORG

# for visualisation of code profile:
# python -m cProfile -o profile.pstats profiler.py
# gprof2dot -f pstats profile.pstats | dot -Tpng -o output.png && eog output.png
from CybORG.Agents.SimpleAgents.Meander import RedMeanderAgent
from CybORG.Agents.Wrappers.BlueTableWrapper import BlueTableWrapper
from CybORG.Agents.Wrappers.EnumActionWrapper import EnumActionWrapper
from CybORG.Agents.Wrappers.OpenAIGymWrapper import OpenAIGymWrapper
from CybORG.Agents.Wrappers.ReduceActionSpaceWrapper import ReduceActionSpaceWrapper


def run():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    red_agent = RedMeanderAgent
    agent_name = 'Red'
    c = OpenAIGymWrapper(agent_name,
                              EnumActionWrapper(
                                  ReduceActionSpaceWrapper(
                                      BlueTableWrapper(
                                          CybORG(path, 'sim', agents={'Red': red_agent}),
                                          output_mode='vector'))))
    for i in range(100):
        for i in range(50):
            c.step()
        c.reset()

# cProfile.run("run()", sort='cumtime')
run()

#cyborg = DummyVecEnv([lambda: cyborg])
# num_cpu = 4
# cyborg = SubprocVecEnv([make_blue_env(red_agent) for i in range(num_cpu)])
