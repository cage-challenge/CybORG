# Copyright DST Group. Licensed under the MIT license.
from ipaddress import IPv4Address, IPv4Network

import numpy as np

from CybORG.Shared.Enums import TrinaryEnum, ProcessName, ProcessType, ProcessVersion, AppProtocol, OperatingSystemType, \
    OperatingSystemVersion, OperatingSystemDistribution, Architecture, SessionType, Path, ProcessState, \
    FileType, Vulnerability, Vendor, FileExt, BuiltInGroups, PasswordHashType
from CybORG.Shared.Observation import Observation

import pytest


@pytest.fixture()
def create_observation():
    observation = Observation()
    return observation


def test_create_blank_observation(create_observation):
    observation = create_observation
    assert len(observation.get_dict()) == 1
    assert type(observation.get_dict()) == dict
    assert observation.get_dict()['success'] == TrinaryEnum.UNKNOWN
    assert type(observation.get_dict()['success']) == TrinaryEnum


@pytest.fixture()
def set_success_true(create_observation):
    observation = create_observation
    observation.set_success(True)
    return observation


def test_set_success_true(set_success_true):
    observation = set_success_true
    assert observation.get_dict()['success'] == TrinaryEnum.TRUE
    assert type(observation.get_dict()['success']) == TrinaryEnum
    return observation


@pytest.fixture()
def set_success_false(create_observation):
    observation = create_observation
    observation.set_success(False)
    return observation


def test_set_success_false(set_success_false):
    observation = set_success_false
    assert observation.get_dict()['success'] == TrinaryEnum.FALSE
    assert type(observation.get_dict()['success']) == TrinaryEnum


def test_add_no_process(create_observation):
    observation = create_observation
    observation.add_process()
    assert len(observation.get_dict()) == 1
    assert type(observation.get_dict()) == dict


@pytest.mark.parametrize('pids', [[1], [2845], [1, 2, 3], [1, 1, 1], [1, 2, 1, 5, 3, 6, 8, 4, 1], list(range(1000))])
def test_add_pids_process_single_host(create_observation, pids):
    observation = create_observation
    for p in pids:
        observation.add_process(hostid="test", pid=p)
    assert len(observation.get_dict()) == 2
    assert type(observation.get_dict()) == dict
    new_host = observation.get_dict()["test"]
    u_pids = np.unique(np.array(pids))
    assert len(new_host["Processes"]) == len(u_pids)
    for pid in u_pids:
        success = False
        for proc in new_host["Processes"]:
            if proc["PID"] == pid:
                success = True
        assert success, f"PID {pid} not added to process observation"


@pytest.mark.parametrize('pids', [[1], [2845], [1, 2, 3], [1, 1, 1], [1, 2, 1, 5, 3, 6, 8, 4, 1], list(range(1000))])
def test_add_pids_process_many_hosts(create_observation, pids):
    observation = create_observation
    for p in pids:
        observation.add_process(pid=p)
    assert len(observation.get_dict()) == len(pids) + 1
    assert type(observation.get_dict()) == dict
    for pid in pids:
        success = False
        for key, host in list(observation.get_dict().items()):
            if key != 'success':
                if host["Processes"][0]["PID"] == pid:
                    success = True
                    break
        assert success, f"PID {pid} not added to process observation"
    for key, host in observation.get_dict().items():
        if key != 'success':
            assert len(host["Processes"]) == 1

@pytest.fixture()
def add_info_process_1(create_observation):
    observation = create_observation
    observation.add_process(hostid="test", pid=1)
    return observation


def test_add_info_process_1(add_info_process_1):
    observation = add_info_process_1
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1


@pytest.fixture()
def add_info_process_2(add_info_process_1):
    observation = add_info_process_1
    observation.add_process(hostid="test", pid=1, parent_pid=2)
    return observation


def test_add_info_process_2(add_info_process_2):
    observation = add_info_process_2
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1
    assert observation.get_dict()["test"]["Processes"][0]["PPID"] == 2


@pytest.fixture()
def add_info_process_3(add_info_process_2):
    observation = add_info_process_2
    observation.add_process(hostid="test", pid=1, process_name="hello")
    return observation


def test_add_info_process_3(add_info_process_3):
    observation = add_info_process_3
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1
    assert observation.get_dict()["test"]["Processes"][0]["PPID"] == 2
    assert observation.get_dict()["test"]["Processes"][0]["Process Name"] == "hello"
    assert observation.get_dict()["test"]["Processes"][0]["Known Process"] == ProcessName.UNKNOWN


@pytest.fixture()
def add_info_process_4(add_info_process_3):
    observation = add_info_process_3
    observation.add_process(hostid="test", pid=1, process_type="SSH")
    return observation


def test_add_info_process_4(add_info_process_4):
    observation = add_info_process_4
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1
    assert observation.get_dict()["test"]["Processes"][0]["PPID"] == 2
    assert observation.get_dict()["test"]["Processes"][0]["Process Name"] == "hello"
    assert observation.get_dict()["test"]["Processes"][0]["Known Process"] == ProcessName.UNKNOWN
    assert observation.get_dict()["test"]["Processes"][0]["Process Type"] == ProcessType.SSH


@pytest.fixture()
def add_info_process_5(add_info_process_4):
    observation = add_info_process_4
    observation.add_process(hostid="test", pid=1, process_version="OpenSSH 1.3")
    return observation


def test_add_info_process_5(add_info_process_5):
    observation = add_info_process_5
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1
    assert observation.get_dict()["test"]["Processes"][0]["PPID"] == 2
    assert observation.get_dict()["test"]["Processes"][0]["Process Name"] == "hello"
    assert observation.get_dict()["test"]["Processes"][0]["Known Process"] == ProcessName.UNKNOWN
    assert observation.get_dict()["test"]["Processes"][0]["Process Type"] == ProcessType.SSH
    assert observation.get_dict()["test"]["Processes"][0]["Process Version"] == ProcessVersion.OPENSSH_1_3


@pytest.fixture()
def add_network_process_info_1(create_observation):
    observation = create_observation
    # add single listening UDP port
    observation.add_process(hostid="test", pid=1, local_address="0.0.0.0", local_port=80, app_protocol="HTTP")
    return observation


def test_add_network_process_info_1(add_network_process_info_1):
    observation = add_network_process_info_1
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1
    assert len(observation.get_dict()["test"]["Processes"][0]["Connections"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_address"] == IPv4Address("0.0.0.0")
    assert "remote_address" not in observation.get_dict()["test"]["Processes"][0]["Connections"][0]
    assert "remote_port" not in observation.get_dict()["test"]["Processes"][0]["Connections"][0]
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_port"] == 80
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["Application Protocol"] == AppProtocol.HTTP


@pytest.fixture()
def add_network_process_info_2(add_network_process_info_1):
    observation = add_network_process_info_1
    # add a remote HTTP connection
    observation.add_process(hostid="test", pid=1, remote_port=80, remote_address="10.0.0.1", app_protocol="TCP")
    return observation


def test_add_network_process_info_2(add_network_process_info_2):
    observation = add_network_process_info_2
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1
    assert len(observation.get_dict()["test"]["Processes"][0]["Connections"]) == 2
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_address"] == IPv4Address("0.0.0.0")
    assert "remote_address" not in observation.get_dict()["test"]["Processes"][0]["Connections"][0]
    assert "remote_port" not in observation.get_dict()["test"]["Processes"][0]["Connections"][0]
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_port"] == 80
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["Application Protocol"] == AppProtocol.HTTP

    assert observation.get_dict()["test"]["Processes"][0]["Connections"][1]["remote_address"] == IPv4Address("10.0.0.1")
    assert "local_address" not in observation.get_dict()["test"]["Processes"][0]["Connections"][1]
    assert "local_port" not in observation.get_dict()["test"]["Processes"][0]["Connections"][1]
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][1]["remote_port"] == 80
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][1]["Application Protocol"] == AppProtocol.TCP


@pytest.fixture()
def add_network_process_info_3(add_network_process_info_2):
    observation = add_network_process_info_2
    # add local ephemeral port connection
    observation.add_process(hostid="test", pid=1, local_port=52435, local_address="10.0.0.2", app_protocol="TCP")
    return observation


def test_add_network_process_info_3(add_network_process_info_3):
    observation = add_network_process_info_3
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 1
    assert len(observation.get_dict()["test"]["Processes"][0]["Connections"]) == 3

    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_address"] == IPv4Address("0.0.0.0")
    assert "remote_address" not in observation.get_dict()["test"]["Processes"][0]["Connections"][0]
    assert "remote_port" not in observation.get_dict()["test"]["Processes"][0]["Connections"][0]
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_port"] == 80
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["Application Protocol"] == AppProtocol.HTTP

    assert observation.get_dict()["test"]["Processes"][0]["Connections"][1]["remote_address"] == IPv4Address("10.0.0.1")
    assert "local_address" not in observation.get_dict()["test"]["Processes"][0]["Connections"][1]
    assert "local_port" not in observation.get_dict()["test"]["Processes"][0]["Connections"][1]
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][1]["remote_port"] == 80
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][1]["Application Protocol"] == AppProtocol.TCP

    assert observation.get_dict()["test"]["Processes"][0]["Connections"][2]["local_address"] == IPv4Address("10.0.0.2")
    assert "remote_address" not in observation.get_dict()["test"]["Processes"][0]["Connections"][2]
    assert "remote_port" not in observation.get_dict()["test"]["Processes"][0]["Connections"][2]
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][2]["local_port"] == 52435
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][2]["Application Protocol"] == AppProtocol.TCP


def test_add_negative_pid_process(create_observation):
    observation = create_observation
    success = True
    try:
        observation.add_process(hostid="test", pid=-1)
    except ValueError:
        success = False
    if success:
        pytest.fail("Negative pid successfully added")


@pytest.fixture()
def add_all_process_info(create_observation):
    observation = create_observation
    observation.add_process(hostid="test", pid=123, parent_pid=23, process_name="svchost", program_name="svchost",
                            username="NT Authority/System", path="C:/Windows/System32/", local_port=32421,
                            remote_port=443, local_address="10.0.0.1", remote_address="10.0.0.2", app_protocol="TCP",
                            status="Open", process_type="?????", process_version="10.0.17763.1",
                            vulnerability="ms10-040")
    return observation


def test_all_process_info(add_all_process_info):
    observation = add_all_process_info
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["PID"] == 123
    assert observation.get_dict()["test"]["Processes"][0]["PPID"] == 23
    assert observation.get_dict()["test"]["Processes"][0]["Process Name"] == "svchost"
    assert observation.get_dict()["test"]["Processes"][0]["Known Process"] == ProcessName.SVCHOST
    assert observation.get_dict()["test"]["Processes"][0]["Program Name"] == FileType.SVCHOST
    assert observation.get_dict()["test"]["Processes"][0]["Username"] == "NT Authority/System"
    assert observation.get_dict()["test"]["Processes"][0]["Path"] == "C:/Windows/System32/"
    assert observation.get_dict()["test"]["Processes"][0]["Known Path"] == Path.WINDOWS_SYSTEM

    assert len(observation.get_dict()["test"]["Processes"][0]["Connections"]) == 1
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_address"] == IPv4Address("10.0.0.1")
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["remote_address"] == IPv4Address("10.0.0.2")
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["local_port"] == 32421
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["remote_port"] == 443
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["Application Protocol"] == AppProtocol.TCP
    assert observation.get_dict()["test"]["Processes"][0]["Connections"][0]["Status"] == ProcessState.OPEN

    assert observation.get_dict()["test"]["Processes"][0]["Process Type"] == ProcessType.UNKNOWN
    assert observation.get_dict()["test"]["Processes"][0]["Process Version"] == ProcessVersion.SVC10_0_17763_1
    assert observation.get_dict()["test"]["Processes"][0]["Vulnerability"][0] == Vulnerability.UNKNOWN


@pytest.fixture()
def add_system_info(create_observation):
    observation = create_observation
    observation.add_system_info(hostid="test", hostname="TestHost", os_type="Windows", os_distribution="Windows 8",
                                os_version="6.2.9200.16384", architecture="x86")
    return observation


def test_add_system_info(add_system_info):
    observation = add_system_info
    assert len(observation.get_dict()) == 2
    system_info = observation.get_dict()["test"]["System info"]
    assert system_info["Hostname"] == "TestHost"
    assert system_info["OSType"] == OperatingSystemType.WINDOWS
    assert system_info["OSDistribution"] == OperatingSystemDistribution.WINDOWS_8
    assert system_info["OSVersion"] == OperatingSystemVersion.W6_2_9200_16384
    assert system_info["Architecture"] == Architecture.x86


@pytest.fixture()
def add_interface_info(create_observation):
    observation = create_observation
    observation.add_interface_info(hostid="test", interface_name="test_interface", ip_address="10.11.12.13",
                                   subnet="10.11.12.0/24")
    return observation


def test_add_interface_info(add_interface_info):
    observation = add_interface_info
    assert len(observation.get_dict()) == 2
    assert len(observation.get_dict()["test"]["Interface"]) == 1
    interface = observation.get_dict()["test"]["Interface"][0]
    assert interface["Interface Name"] == "test_interface"
    assert interface["IP Address"] == IPv4Address("10.11.12.13")
    assert interface["Subnet"] == IPv4Network("10.11.12.0/24")

@pytest.fixture()
def add_file_info(create_observation):
    observation = create_observation
    observation.add_file_info(hostid="test", path="/tmp/", name="dodgy", vendor="stranger", version="0.1",
                              file_type="nmap", user="root", user_permissions=7, group="1000", group_permissions=7,
                              default_permissions=7)
    return observation


def test_add_file_info(add_file_info):
    observation = add_file_info
    assert len(observation.get_dict()) == 2
    assert len(observation.get_dict()["test"]["Files"]) == 1
    file = observation.get_dict()["test"]["Files"][0]
    assert file["File Name"] == "dodgy"
    assert file["Known File"] == FileType.UNKNOWN
    assert file["Path"] == "/tmp/"
    assert file["Known Path"] == Path.TEMP
    assert file["Vendor"] == Vendor.UNKNOWN
    assert file["Version"] == "0.1"
    assert file["Type"] == FileType.NMAP
    assert file["Username"] == "root"
    assert file["User Permissions"] == 7
    assert file["Group Name"] == "1000"
    assert file["Group Permissions"] == 7
    assert file["Default Permissions"] == 7

    # TODO needs to be completed once the enums are complete


@pytest.fixture()
def add_user_info(create_observation):
    observation = create_observation
    observation.add_user_info(hostid="test", group_name="Users", username="Basic_user",
                              password="password", password_hash="5f4dcc3b5aa765d61d8327deb882cf99", password_hash_type="MD5")
    return observation


def test_add_user_info(add_user_info):
    observation = add_user_info
    assert len(observation.get_dict()) == 2
    assert len(observation.get_dict()["test"]["User Info"]) == 1
    user = observation.get_dict()["test"]["User Info"][0]
    assert user["Username"] == "Basic_user"
    assert len(user["Groups"]) == 1
    assert user["Groups"][0]["Group Name"] == "Users"
    assert user["Groups"][0]["Builtin Group"] == BuiltInGroups.USERS
    assert user["Password"] == "password"
    assert user["Password Hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert user["Password Hash Type"] == PasswordHashType.MD5


@pytest.fixture()
def add_user_info2(add_user_info):
    observation = add_user_info
    observation.add_user_info(hostid="test", group_name="Users", username="Basic_user", uid=1001, gid=1001,
                              password="password", password_hash="5f4dcc3b5aa765d61d8327deb882cf99", password_hash_type="MD5")
    return observation


def test_add_user_info_2(add_user_info2):
    observation = add_user_info2
    assert len(observation.get_dict()) == 2
    assert len(observation.get_dict()["test"]["User Info"]) == 1
    user = observation.get_dict()["test"]["User Info"][0]
    assert user["Username"] == "Basic_user"
    assert user["UID"] == 1001
    assert len(user["Groups"]) == 1
    assert len(user["Groups"][0]) == 3
    assert user["Groups"][0]["Group Name"] == "Users"
    assert user["Groups"][0]["Builtin Group"] == BuiltInGroups.USERS
    assert user["Groups"][0]["GID"] == 1001
    assert user["Password"] == "password"
    assert user["Password Hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert user["Password Hash Type"] == PasswordHashType.MD5

@pytest.fixture()
def add_user_info3(create_observation):
    observation = create_observation
    observation.add_user_info(hostid="test", username="Basic_user", uid=1001, gid=1001)
    observation.add_user_info(hostid="test", username="Basic_user", group_name="Basic_Group", gid=1001)

    return observation


def test_add_user_info_3(add_user_info3):
    observation = add_user_info3
    assert len(observation.get_dict()) == 2
    assert len(observation.get_dict()["test"]["User Info"]) == 1
    user = observation.get_dict()["test"]["User Info"][0]
    assert user["Username"] == "Basic_user"
    assert user["UID"] == 1001
    assert len(user["Groups"]) == 1
    assert len(user["Groups"][0]) == 2
    assert user["Groups"][0]["Group Name"] == "Basic_Group"
    assert user["Groups"][0]["GID"] == 1001


@pytest.fixture()
def add_user_info4(create_observation):
    observation = create_observation
    observation.add_user_info(hostid="test", username="Basic_user", uid=1001, gid=1001)
    observation.add_user_info(hostid="test", group_name="Basic_Group", gid=1001)

    return observation


def test_add_user_info_4(add_user_info4):
    observation = add_user_info4
    assert len(observation.get_dict()) == 2
    assert len(observation.get_dict()["test"]["User Info"]) == 1
    user = observation.get_dict()["test"]["User Info"][0]
    assert user["Username"] == "Basic_user"
    assert user["UID"] == 1001
    assert len(user["Groups"]) == 1
    assert len(user["Groups"][0]) == 2
    assert user["Groups"][0]["Group Name"] == "Basic_Group"
    assert user["Groups"][0]["GID"] == 1001


@pytest.fixture()
def add_user_info5(create_observation):
    observation = create_observation
    observation.add_user_info(hostid="test", group_name="Basic_Group", gid=1001)
    observation.add_user_info(hostid="test", username="Basic_user", uid=1001, gid=1001)
    return observation


# this is a known issue with the current implementation of the observation. The order of adding a group should not affect the solution
# def test_add_user_info_5(add_user_info5):
#     observation = add_user_info5
#     assert len(observation.get_dict()) == 2
#     assert len(observation.get_dict()["test"]["User Info"]) == 1
#     user = observation.get_dict()["test"]["User Info"][0]
#     assert user["Username"] == "Basic_user"
#     assert user["UID"] == 1001
#     assert len(user["Groups"]) == 1
#     assert len(user["Groups"][0]) == 2
#     assert user["Groups"][0]["Group Name"] == "Basic_Group"
#     assert user["Groups"][0]["GID"] == 1001

@pytest.fixture()
def add_session_info(create_observation):
    observation = create_observation
    observation.add_session_info(hostid="test", username="test", session_id=0, timeout=0, pid=432, session_type="ssh", agent="Red")
    return observation


def test_add_session_info(add_session_info):
    observation = add_session_info
    assert len(observation.get_dict()) == 2
    assert len(observation.get_dict()["test"]["Sessions"]) == 1
    session = observation.get_dict()["test"]["Sessions"][0]
    assert session["ID"] == 0
    assert session["Username"] == "test"
    assert session["Timeout"] == 0
    assert session["PID"] == 432
    assert session["Type"] == SessionType.SSH
    assert len(observation.get_dict()["test"]["Processes"]) == 1
    process = observation.get_dict()["test"]["Processes"][0]
    assert process["Username"] == "test"
    assert process["PID"] == 432

def test_repeat_adding_interface_info(create_observation):
    observation = create_observation
    observation.add_interface_info(hostid="test", ip_address="127.0.0.1")
    observation.add_interface_info(hostid="test", ip_address="127.0.0.1")
    assert len(observation.get_dict()["test"]["Interface"]) == 1
