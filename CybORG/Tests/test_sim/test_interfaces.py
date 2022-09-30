import gym.utils.env_checker
import pytest
from pettingzoo.test import parallel_api_test


def test_open_ai_interface(open_ai_wrapped_cyborg):
    # use open_ai gym env check to verify interface
    env = open_ai_wrapped_cyborg
    gym.utils.env_checker.check_env(env)


@pytest.mark.skip('agents are able to return from the dead')
def test_petting_zoo_parallel_interface(pettingzoo_parallel_wrapped_cyborg):
    # use open_ai gym env check to verify interface
    env = pettingzoo_parallel_wrapped_cyborg
    parallel_api_test(env, num_cycles=1000)
