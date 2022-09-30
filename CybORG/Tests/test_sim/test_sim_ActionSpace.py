from ipaddress import IPv4Network, IPv4Address
from random import choice

import pytest

from CybORG.Agents.Wrappers import EnumActionWrapper
from CybORG.Agents.Wrappers import ReduceActionSpaceWrapper
from CybORG.Shared.Actions import MeterpreterIPConfig, MSFAutoroute, MS17_010_PSExec, MSFPortscan, MSFPingsweep, \
    UpgradeToMeterpreter, SSHLoginExploit, Sleep, DiscoverNetworkServices, \
    ExploitRemoteService
from CybORG.Shared.Observation import Observation


@pytest.fixture(params=['Red'])
def create_sim_action_space(request, create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    agent = request.param
    action_space = cyborg.environment_controller.agent_interfaces[agent].action_space
    return action_space, agent


@pytest.fixture(params=[("10.0.0.0/28", {"Blue": False, "Red": True}), ("10.0.0.16/28", {"Blue": True, "Red": True}),
                        ("10.0.3.0/28", {"Blue": False, "Red": False})])
def add_subnet(create_sim_action_space, request):
    action_space, agent = create_sim_action_space
    subnet = IPv4Network(request.param[0])
    allowed = request.param[1][agent]
    obs = Observation()
    obs.add_interface_info(subnet=subnet)
    action_space.update(obs.data)
    return action_space, subnet, allowed


# def test_add_subnet(add_subnet):
#     action_space, subnet, allowed = add_subnet
#     if allowed:
#         assert subnet in action_space.subnet, f"{subnet} not in {action_space.allowed_subnets}"
#     else:
#         assert subnet not in action_space.subnet, "Subnet added to action space that should have been forbidden"


@pytest.fixture(params=[("root", {"Blue": True, "Red": True}), ("vagrant", {"Blue": True, "Red": True})])
def add_user(create_sim_action_space, request):
    action_space, agent = create_sim_action_space
    user = request.param[0]
    allowed = request.param[1][agent]
    obs = Observation()
    obs.add_user_info(username=user)
    action_space.update(obs.data)
    return action_space, user, allowed


def test_add_user(add_user):
    action_space, username, allowed = add_user
    if allowed:
        assert username in action_space.username
    else:
        assert username not in action_space.username, "User added to action space that should have been forbidden"


@pytest.fixture(params=list(range(10)))
def add_session(create_sim_action_space, request):
    action_space, agent = create_sim_action_space
    session = request.param
    obs = Observation()
    obs.add_session_info(session_id=session, agent=agent)
    action_space.update(obs.data)
    return action_space, session


def test_add_session(add_session):
    action_space, session = add_session
    assert session in action_space.client_session
    assert action_space.client_session[session]


@pytest.fixture(params=[(5423, {"Blue": True, "Red": True}), (4, {"Blue": True, "Red": True}),
                        (773, {"Blue": True, "Red": True})])
def add_process(create_sim_action_space, request):
    action_space, agent = create_sim_action_space
    process = request.param[0]
    allowed = request.param[1][agent]
    obs = Observation()
    obs.add_process(pid=process)
    action_space.update(obs.data)
    return action_space, process, allowed


def test_add_process(add_process):
    action_space, process, allowed = add_process
    if allowed:
        assert process in action_space.process
    else:
        assert process not in action_space.process, "Process added to action space that should have been forbidden"


@pytest.fixture(
    params=[(22, {"Blue": True, "Red": True}), (8180, {"Blue": True, "Red": True}), (80, {"Blue": True, "Red": True})])
def add_port(create_sim_action_space, request):
    action_space, agent = create_sim_action_space
    port = request.param[0]
    allowed = request.param[1][agent]
    obs = Observation()
    obs.add_process(local_port=port)
    action_space.update(obs.data)
    return action_space, port, allowed


def test_add_port(add_port):
    action_space, port, allowed = add_port
    if allowed:
        assert port in action_space.port
    else:
        assert port not in action_space.port, "Port added to action space that should have been forbidden"


@pytest.fixture(params=[("10.0.0.1", {"Blue": False, "Red": True}), ("10.0.3.1", {"Blue": False, "Red": False})])
def add_ip_address(create_sim_action_space, request):
    action_space, agent = create_sim_action_space
    ip_address = IPv4Address(request.param[0])
    allowed = request.param[1][agent]
    obs = Observation()
    obs.add_interface_info(ip_address=ip_address)
    action_space.update(obs.data)
    return action_space, ip_address, allowed


@pytest.fixture()
def reboot(create_cyborg_sim):
    agent = 'Red'
    cyborg, scenario = create_cyborg_sim
    if scenario == 'Scenario1':
        address = cyborg.environment_controller.hostname_ip_map['Internal']
        action = MSFPortscan(ip_address=address, session=0, agent=agent)
        cyborg.step(agent, action, skip_valid_action_check=True)
        action = SSHLoginExploit(ip_address=address, agent=agent, session=0, port=22)
        cyborg.step(agent, action)
        action = UpgradeToMeterpreter(session=0, agent='Red', target_session=1)
        cyborg.step(agent, action)
        hostname = 'Internal'
    elif scenario == 'Scenario1b':
        address = cyborg.environment_controller.hostname_ip_map['User1']
        action = DiscoverNetworkServices(ip_address=address, session=0, agent=agent)
        cyborg.step(agent, action)
        action = ExploitRemoteService(ip_address=address, agent=agent, session=0)
        cyborg.step(agent, action)
        hostname = 'User1'
    else:
        raise ValueError(f"Unaccounted for scenario: {scenario}")

    state = cyborg.environment_controller.state
    return cyborg, state, hostname


# def test_add_ip_address(add_ip_address):
#     action_space, ip_address, allowed = add_ip_address
#     if allowed:
#         assert ip_address in action_space.ip_address, f"{ip_address} not in {action_space.allowed_subnets}"
#     else:
#         assert ip_address not in action_space.ip_address, \
#             "Ip_address added to action space that should have been forbidden"


def test_update_action_space_from_observation_process(create_sim_action_space):
    action_space, agent = create_sim_action_space
    obs = Observation()
    obs.add_process(pid=1643)
    action_space.update(obs.data)
    assert 1643 in action_space.process


def test_update_action_space_from_observation_interface(create_sim_action_space):
    action_space, agent = create_sim_action_space
    subnet = list(action_space.subnet.keys())[0]
    obs = Observation()
    obs.add_interface_info(ip_address=list(subnet.hosts())[-1], subnet=subnet)
    action_space.update(obs.data)
    assert list(subnet.hosts())[-1] in action_space.ip_address
    assert action_space.subnet[subnet] == True


def test_update_action_space_from_observation_user(create_sim_action_space):
    action_space, agent = create_sim_action_space
    obs = Observation()
    obs.add_user_info(group_name='root', gid=0, username='root', uid=0, password='password')
    action_space.update(obs.data)
    assert 'root' in action_space.username
    assert 'password' in action_space.password


def test_update_action_space_from_observation_session(create_sim_action_space):
    action_space, agent = create_sim_action_space
    obs = Observation()
    obs.add_session_info(session_id=5, agent=agent)
    action_space.update(obs.data)
    assert 5 in action_space.client_session

def test_action_space_scenario1_sized(create_cyborg_sim):
    cyborg, scenario = create_cyborg_sim
    if scenario == 'Scenario1':
        pytest.skip('Scenario1 has an expanding number of ports due to observation of ephemeral ports')
    cyborg = EnumActionWrapper(ReduceActionSpaceWrapper(cyborg))
    action_space = cyborg.get_action_space('Red')
    for j in range(10):
        for i in range(100):
            action = choice(range(action_space))
            # print(action)
            cyborg.step(action=action, agent='Red')
            old_action_space = action_space
            action_space = cyborg.get_action_space('Red')
            assert action_space == old_action_space, f'action {i}: {action} {cyborg.get_last_action(agent="Red")} with observation {cyborg.get_observation("Red")} resulted in change in action_space size'
        res = cyborg.reset('Red')
        action_space = res.action_space


def test_reboot(reboot):
    cyborg, state, hostname = reboot
    state.reboot_host(hostname)
    action_space = cyborg.get_action_space('Red')
    assert sum(value is True for value in action_space['session'].values()) == 1


# def test_reboot_persistence(reboot):
#     agent = 'Red'
#     cyborg = reboot.cyborg
#
#     action = ServicePersistenceWindows(session=0, agent='Red', target_session=2)
#     cyborg.step(agent, action)
#     state = cyborg.environment_controller.state
#
#     state.reboot_host('Internal')
#     action_space = cyborg.get_action_space(agent)
#     assert sum(value is True for value in action_space['target_session'].values()) == 1
