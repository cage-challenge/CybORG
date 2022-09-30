import random

import pytest

from CybORG.Agents.Wrappers import FixedFlatWrapper
from CybORG.Agents.Wrappers.EnumActionWrapper import EnumActionWrapper
from CybORG.Agents.Wrappers.IntListToAction import IntListToActionWrapper


def test_intlist_to_action_wrapper_action_space(create_cyborg_sim):
    cyborg = create_cyborg_sim
    wrapped_cyborg = IntListToActionWrapper(cyborg)
    scenario = str(cyborg.scenario_generator).split('/')[-1].rstrip('.yaml')

    result = wrapped_cyborg.step(agent='Red')
    assert type(result.action_space) is list, f"Action space {wrapped_cyborg.param_name}"

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red', seed=123)
    assert type(result.action_space) is list, f"Action space {wrapped_cyborg.param_name}"

    if scenario == 'Scenario1':
        pytest.skip('Scenario1 not currently supported due to expanding action space')
    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected = [8, 3, 4, 9, 2, 9, 8]
    elif scenario == 'Scenario1b':
        expected = [6, 3, 16, 16]
    elif scenario == 'Scenario2':
        expected = [15, 3, 16, 16]
    else:
        raise ValueError(f'Scenario {scenario} not supported by this test')

    assert expected == result.action_space

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red', seed=123)
    assert expected == result.action_space

    result = wrapped_cyborg.step(agent='Red')
    assert expected == result.action_space

    # run the game and check that the action space remains a consistent size
    for i in range(100):
        result = wrapped_cyborg.step(agent='Red', action=[random.randint(0, j-1) for j in result.action_space])
        assert expected == result.action_space
        assert type(result.action_space) is list, f"Action space {wrapped_cyborg.param_name}"


def test_flat_fixed_wrapper_observation_space(create_cyborg_sim):
    cyborg = create_cyborg_sim
    wrapped_cyborg = FixedFlatWrapper(IntListToActionWrapper(cyborg))
    scenario = str(cyborg.scenario_generator).split('/')[-1].rstrip('.yaml')
    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected_obs_space = 11293
    elif scenario == 'Scenario1b':
        expected_obs_space = 11293
    else:
        # raise ValueError(f'Scenario {scenario} not supported by this test')
        pytest.skip(f'Scenario {scenario} not supported by this test')

    result = wrapped_cyborg.step(agent='Red')
    assert len(result.observation) == expected_obs_space

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red')
    assert len(result.observation) == expected_obs_space

    # run the game and check that the action space remains a consistent size
    for i in range(100):
        result = wrapped_cyborg.step(agent='Red', action=[random.randint(0, j-1) for j in result.action_space])
        assert len(result.observation) == expected_obs_space


def test_EnumActionWrapper(create_cyborg_sim):
    cyborg = create_cyborg_sim
    scenario = str(cyborg.scenario_generator).split('/')[-1].rstrip('.yaml').rstrip('.yaml')
    wrapped_cyborg = EnumActionWrapper(cyborg)
    if scenario == 'Scenario1':
        pytest.skip('Scenario1 not currently supported due to expanding action space')
    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected_action_space = 161
    elif scenario == 'Scenario1b':
        expected_action_space = 68
    else:
        # raise ValueError(f'Scenario {scenario} not supported by this test')
        pytest.skip(f'Scenario {scenario} not supported by this test')

    result = wrapped_cyborg.step(agent='Red')
    assert result.action_space == expected_action_space

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red')
    assert result.action_space == expected_action_space

    # run the game and check that the action space remains a consistent size
    for i in range(100):
        result = wrapped_cyborg.step(agent='Red', action=random.randint(0, result.action_space-1))
        assert result.action_space == expected_action_space


def test_flat_fixed_wrapper_enum_actions_observation_space(create_cyborg_sim):
    cyborg = create_cyborg_sim
    wrapped_cyborg = FixedFlatWrapper(EnumActionWrapper(cyborg))
    scenario = str(cyborg.scenario_generator).split('/')[-1].rstrip('.yaml')
    # if scenario == 'Scenario1':
    #     pytest.skip('Scenario1 not currently supported')

    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected_obs_space = 11293
    elif scenario == 'Scenario1b':
        expected_obs_space = 11293
    else:
        # raise ValueError(f'Scenario {scenario} not supported by this test')
        pytest.skip(f'Scenario {scenario} not supported by this test')

    result = wrapped_cyborg.step(agent='Red')
    assert len(result.observation) == expected_obs_space

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red')
    assert len(result.observation) == expected_obs_space

    # run the game and check that the action space remains a consistent size
    for i in range(100):
        result = wrapped_cyborg.step(agent='Red', action=random.randint(0, result.action_space-1))
        assert len(result.observation) == expected_obs_space

@pytest.mark.parametrize(('attribute', 'wrappers'), [('possible_actions', [EnumActionWrapper]),
                                                     ('possible_actions', [FixedFlatWrapper, EnumActionWrapper]),
                                                     ('possible_actions', [EnumActionWrapper, FixedFlatWrapper])])
def test_get_attr_success(create_cyborg_sim, attribute: str, wrappers: list):
    cyborg = create_cyborg_sim
    for wrapper in wrappers:
        cyborg = wrapper(cyborg)
    value = cyborg.get_attr(attribute)
    assert value is not None

@pytest.mark.parametrize(('attribute', 'wrappers'), [('does_not_exist', [EnumActionWrapper]),
                                                     ('does_not_exist', [FixedFlatWrapper, EnumActionWrapper]),
                                                     ('does_not_exist', [EnumActionWrapper, FixedFlatWrapper]),
                                                     ('possible_actions', [FixedFlatWrapper])])
def test_get_attr_fail(create_cyborg_sim, attribute: str, wrappers: list):
    cyborg = create_cyborg_sim
    for wrapper in wrappers:
        cyborg = wrapper(cyborg)
    value = cyborg.get_attr(attribute)
    assert value is None
