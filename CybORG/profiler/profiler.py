import cProfile
import inspect

from CybORG import CybORG

# for visualisation of code profile:
# python -m cProfile -o profile.pstats profiler.py
# gprof2dot -f pstats profile.pstats | dot -Tpng -o output.png && eog output.png
from CybORG.Emulator.AWS import AWSConfig


def run():
    aws = True
    if not aws:
        c = CybORG(path, 'sim')
    else:
        c = CybORG(path, 'aws', env_config={"config": AWSConfig.load_and_setup_logger(test=True),"create_tunnel": False})
    try:
        for i in range(1):
            c.start(50)
            # c.reset()
    finally:
        c.shutdown(teardown=True)
path = str(inspect.getfile(CybORG))
path = path[:-10] + '/Shared/Scenarios/Scenario1.yaml'
# cProfile.run("run()", sort='cumtime')
run()



