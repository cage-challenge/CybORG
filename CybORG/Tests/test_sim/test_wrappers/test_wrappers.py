import random
from ipaddress import IPv4Address, IPv4Network

from CybORG.Agents.Wrappers import FixedFlatWrapper
from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper
from CybORG.Agents.Wrappers.EnumActionWrapper import EnumActionWrapper
from CybORG.Agents.Wrappers.IntListToAction import IntListToActionWrapper
from CybORG.Agents.Wrappers.ReduceActionSpaceWrapper import ReduceActionSpaceWrapper
from CybORG.Shared.Actions import PrivilegeEscalate, MS17_010_PSExec, UpgradeToMeterpreter, SSHLoginExploit, \
    MeterpreterIPConfig, MSFAutoroute, MSFPingsweep, MSFPortscan, GetFileInfo, GetProcessList, GetProcessInfo, \
    VelociraptorPoll, GetLocalGroups, GetUsers, GetOSInfo, Sleep, Impact, Monitor, Analyse, Restore, Remove, \
    DiscoverNetworkServices, DiscoverRemoteSystems, ExploitRemoteService

import pytest


@pytest.mark.skip
def test_reduce_action_space(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    wrapped_cyborg = ReduceActionSpaceWrapper(cyborg)

    # create function to generate relevant action space
    if scenario == 'Scenario1':
        def expected_action_space(cyborg):
            return {'action': {MS17_010_PSExec: True,
                               UpgradeToMeterpreter: True,
                               Sleep: True,
                               SSHLoginExploit: True,
                               MeterpreterIPConfig: True,
                               MSFAutoroute: True,
                               MSFPortscan: True,
                               MSFPingsweep: True},
                    'agent': {'Red': True},
                    'ip_address': {cyborg.environment_controller.hostname_ip_map['Attacker']: True,
                                   cyborg.environment_controller.hostname_ip_map['Gateway']: True,
                                   cyborg.environment_controller.hostname_ip_map['Internal']: False,
                                   cyborg.environment_controller.hostname_ip_map['Defender']: False},
                    'password': {'raspberry': False, 'vagrant': False},
                    'port': {22: False,
                             68: False,
                             80: False,
                             135: False,
                             139: False,
                             443: False,
                             445: False,
                             3389: False,
                             55553: False},
                    'session': {0: True},
                    'subnet': {cyborg.environment_controller.subnet_cidr_map['Attacker_Network']: True,
                               cyborg.environment_controller.subnet_cidr_map['Defender_Network']: False,
                               cyborg.environment_controller.subnet_cidr_map['Private_Network']: True},
                    'target_session': {0: False,
                                       1: False,
                                       2: False,
                                       3: False,
                                       4: False,
                                       5: False,
                                       6: False,
                                       7: False},
                    'username': {'Administrator': False,
                                 'GreenAgent': False,
                                 'SYSTEM': False,
                                 'ec2-user': False,
                                 'pi': False,
                                 'root': False,
                                 'ubuntu': False,
                                 'vagrant': False,
                                 'www-data': False}}
    elif scenario == 'Scenario1b':
        def expected_action_space(cyborg):
            return {'action': {Sleep: True,
                               DiscoverRemoteSystems: True,
                               DiscoverNetworkServices: True,
                               ExploitRemoteService: True,
                               PrivilegeEscalate: True,
                               Impact: True},
                    'subnet': {cyborg.environment_controller.subnet_cidr_map['User']: True,
                               cyborg.environment_controller.subnet_cidr_map[
                                   'Enterprise']: False,
                               cyborg.environment_controller.subnet_cidr_map[
                                   'Operational']: False,
                               cyborg.environment_controller.subnet_cidr_map[
                                   'Operational']: False},
                    'agent': {'Red': True},
                    'session': {0: True},
                    'ip_address': {
                        cyborg.environment_controller.hostname_ip_map['User0']: True,
                        cyborg.environment_controller.hostname_ip_map['User1']: False,
                        cyborg.environment_controller.hostname_ip_map['User2']: False,
                        cyborg.environment_controller.hostname_ip_map['User3']: False,
                        cyborg.environment_controller.hostname_ip_map['User4']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Enterprise0']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Enterprise1']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Enterprise2']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Defender']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Op_Host0']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Op_Host1']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Op_Host2']: False,
                        cyborg.environment_controller.hostname_ip_map[
                            'Op_Server0']: False
                    },
                    'hostname': {'User0': True,
                                 'User1': False,
                                 'User2': False,
                                 'User3': False,
                                 'User4': False,
                                 'Enterprise0': False,
                                 'Enterprise1': False,
                                 'Enterprise2': False,
                                 'Defender': False,
                                 'Op_Host0': False,
                                 'Op_Host1': False,
                                 'Op_Host2': False,
                                 'Op_Server0': False
                                 },
                    }
    else:
        raise ValueError(f'Scenario {scenario} not supported by this test')

    result = wrapped_cyborg.step(agent='Red')
    assert expected_action_space(cyborg) == result.action_space

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red')
    assert expected_action_space(cyborg) == result.action_space

    result = wrapped_cyborg.step(agent='Red')
    assert expected_action_space(cyborg) == result.action_space


@pytest.mark.skip
def test_intlist_to_action_wrapper_action_space(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    wrapped_cyborg = IntListToActionWrapper(cyborg)

    result = wrapped_cyborg.step(agent='Red')
    assert type(result.action_space) is list, f"Action space {wrapped_cyborg.param_name}"

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red')
    assert type(result.action_space) is list, f"Action space {wrapped_cyborg.param_name}"
    for i in range(100):
        result = wrapped_cyborg.step(agent='Red', action=[random.randint(0, j-1) for j in result.action_space])
        assert type(result.action_space) is list, f"Action space {wrapped_cyborg.param_name}"


@pytest.mark.skip
def test_reduced_intlist_to_action_wrapper_action_space(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    wrapped_cyborg = ReduceActionSpaceWrapper(IntListToActionWrapper(cyborg))

    if scenario == 'Scenario1':
        pytest.skip('Scenario1 not currently supported due to expanding action space')
    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected = [8, 3, 4, 9, 2, 9, 8]
    elif scenario == 'Scenario1b':
        expected = [6, 3, 13, 13]
    else:
        raise ValueError(f'Scenario {scenario} not supported by this test')
    result = wrapped_cyborg.step(agent='Red')
    assert expected == result.action_space

    # test that reset returns correct action space
    result = wrapped_cyborg.reset('Red')
    assert expected == result.action_space

    result = wrapped_cyborg.step(agent='Red')
    assert expected == result.action_space

    # run the game and check that the action space remains a consistent size
    for i in range(100):
        result = wrapped_cyborg.step(agent='Red', action=[random.randint(0, j-1) for j in result.action_space])
        assert expected == result.action_space


def test_flat_fixed_wrapper_observation_space(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    wrapped_cyborg = FixedFlatWrapper(IntListToActionWrapper(ReduceActionSpaceWrapper(cyborg)))

    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected_obs_space = 11293
    elif scenario == 'Scenario1b':
        expected_obs_space = 11293
    else:
        raise ValueError(f'Scenario {scenario} not supported by this test')

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
    cyborg, scenario = create_cyborg_sim
    wrapped_cyborg = EnumActionWrapper(ReduceActionSpaceWrapper(cyborg))
    if scenario == 'Scenario1':
        pytest.skip('Scenario1 not currently supported due to expanding action space')
    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected_action_space = 161
    elif scenario == 'Scenario1b':
        expected_action_space = 56
    else:
        raise ValueError(f'Scenario {scenario} not supported by this test')

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
    cyborg, scenario = create_cyborg_sim
    wrapped_cyborg = FixedFlatWrapper(EnumActionWrapper(ReduceActionSpaceWrapper(cyborg)))
    # if scenario == 'Scenario1':
    #     pytest.skip('Scenario1 not currently supported')

    # create function to generate relevant action space
    if scenario == 'Scenario1':
        expected_obs_space = 11293
    elif scenario == 'Scenario1b':
        expected_obs_space = 11293
    else:
        raise ValueError(f'Scenario {scenario} not supported by this test')

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
    cyborg, scenario = create_cyborg_sim
    for wrapper in wrappers:
        cyborg = wrapper(cyborg)
    value = cyborg.get_attr(attribute)
    assert value is not None

@pytest.mark.parametrize(('attribute', 'wrappers'), [('does_not_exist', [EnumActionWrapper]),
                                                     ('does_not_exist', [FixedFlatWrapper, EnumActionWrapper]),
                                                     ('does_not_exist', [EnumActionWrapper, FixedFlatWrapper]),
                                                     ('possible_actions', [FixedFlatWrapper])])
def test_get_attr_fail(create_cyborg_sim, attribute: str, wrappers: list):
    cyborg, scenario = create_cyborg_sim
    for wrapper in wrappers:
        cyborg = wrapper(cyborg)
    value = cyborg.get_attr(attribute)
    assert value is None

