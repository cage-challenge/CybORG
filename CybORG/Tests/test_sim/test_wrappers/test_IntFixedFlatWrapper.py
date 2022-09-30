import random

import pytest

from CybORG.Agents.Wrappers import IntFixedFlatWrapper
from CybORG.Agents.Wrappers.IntListToAction import IntListToActionWrapper


def test_flat_fixed_wrapper_observation_space(create_cyborg_sim):
    cyborg = create_cyborg_sim
    wrapped_cyborg = IntFixedFlatWrapper(IntListToActionWrapper(cyborg))
    scenario = str(cyborg.scenario_generator).split('/')[-1].rstrip('.yaml')
    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected_obs_space = 577
    elif scenario == 'Scenario1b':
        expected_obs_space = 577
    else:
        pytest.skip(f'Scenario {scenario} not supported by this test')
        # raise ValueError(f'Scenario {scenario} not supported by this test')
    # initial obs
    observation = wrapped_cyborg.get_observation('Red')
    assert len(observation) == expected_obs_space
    for i, element in enumerate(observation):
        assert type(element) is int
        assert element >= -1
        assert element <= 100, f'error {element} > 100 at index {i} with original observaiton {cyborg.get_observation("Red")}'


   # step obs
    result = wrapped_cyborg.step(agent='Red')
    print([(i, j) for i, j in zip(observation, result.observation)])
    assert len(result.observation) == expected_obs_space
    for element in result.observation:
        assert type(element) is int
        assert element >= -1
        assert element <= 100
    # k = result.observation

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red')

    assert len(result.observation) == expected_obs_space
    for element in result.observation:
        assert type(element) is int
        assert element >= -1
        assert element <= 100

    # run the game and check that the action space remains a consistent size
    for i in range(100):
        result = wrapped_cyborg.step(agent='Red', action=[random.randint(0, j-1) for j in result.action_space])
        assert len(result.observation) == expected_obs_space
        for element in result.observation:
            assert type(element) is int
            assert element >= -1
            assert element <= 100