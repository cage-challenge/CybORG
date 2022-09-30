## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.

"""These tests check that the Blue Misinform action is working vs Abstract Red Actions.

tests need to check that a range of inputs result in the correct changes to the
state and return the correct obs
tests should establish varying environmental states that results in these actions
performing differently
"""
# pylint: disable=import-error
# pylint has trouble with this being in test subdirectory
import inspect
import pprint
from typing import Optional, Tuple
from ipaddress import IPv4Address

import pytest

from CybORG import CybORG
from CybORG.Shared.Actions import (
    DiscoverNetworkServices,
    DiscoverRemoteSystems,
    ExploitRemoteService,
    Misinform,
)

from CybORG.Shared.Actions.ConcreteActions.EscalateAction import EscalateAction
from CybORG.Simulator.State import State
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process

from CybORG.Agents import B_lineAgent

from CybORG.Shared.Actions.AbstractActions.Misinform import (
        tomcat_decoy_factory,
        DecoyFactory,
        Decoy
        )

from CybORG.Shared.Actions.AbstractActions.PrivilegeEscalate import (
        EscalateActionSelector, PrivilegeEscalate
        )
from CybORG.Shared.Actions.ConcreteActions.V4L2KernelExploit import V4L2KernelExploit
from CybORG.Shared.Enums import TrinaryEnum, DecoyType
from CybORG.Shared import Observation

class DummyEscalateAction(EscalateAction):
    """
    Requires smss.exe to be running and valid
    """
    def sim_execute(self, state: State) -> Observation:
        """
        Escalates to SYSTEM
        """
        return self.sim_escalate(state, "SYSTEM")

    def test_exploit_works(self, target_host:Host) ->\
            Tuple[bool, Tuple[Process, ...]]:
        # pylint: disable=no-self-use
        """
        Requires smss.exe to be running and valid
        """
        for proc in target_host.processes:
            print(f"proc: {proc}")
            if proc.name == "smss.exe":
                print (f"Found Necessary process: {proc}")
                return (True, (proc,))
        return (False, ())

class DummyEscalateActionSelector(EscalateActionSelector):
    """
    Attempts to use DummyEscalateAction if smss.exe is present, otherwise v4l2kernel
    """
    # pylint: disable=missing-function-docstring
    # pylint: disable=too-few-public-methods
    def get_escalate_action(self, *, state: State, session: int, target_session: int,
            agent: str, hostname: str) -> \
                    Optional[EscalateAction]:
        # pylint: disable=no-self-use
        del hostname
        session_obj = state.sessions[agent][target_session]
        target_host: Host = state.hosts[session_obj.host]

        for proc in target_host.processes:
            if proc.name == "smss.exe":
                return DummyEscalateAction(session=session,
                        target_session=target_session,
                        agent=agent)

        return V4L2KernelExploit(session=session, target_session=target_session,
                agent=agent)

_dummy_escalate_action_selector = DummyEscalateActionSelector()

class _DummyEscalateDecoyFactory(DecoyFactory):
    # pylint: disable=no-self-use
    """Makes a decoy that makes a fake smss, requires that smss is not present"""
    def make_decoy(self, host: Host) -> Decoy:
        """fakes smss.exe"""
        del host
        return Decoy(service_name="smss",  name="smss.exe",
                open_ports=[], process_type="smb")

    def is_host_compatible(self, host: Host) -> bool:
        """requires smss.exe is not present"""
        return not any (p.name == "smss.exe" for p in host.processes)

_dummy_escalate_decoy_factory = _DummyEscalateDecoyFactory()

def _red_scan(cyborg: CybORG):
    """has red agent do a scan on the network"""
    # Discover Remote Systems
    action_space = cyborg.get_action_space('Red')
    _initial_observation = cyborg.get_observation('Red')
    session = list(action_space['session'].keys())[0]
    for subnet in action_space["subnet"]:
        action = DiscoverRemoteSystems(subnet=subnet, agent='Red',
                session=session)
        _result = cyborg.step(action=action, agent='Red')

    # Discover Network Services
    addresses = list(action_space["ip_address"])
    for address in addresses:
        action = DiscoverNetworkServices(agent='Red', ip_address=address,
                session=session)
        _result = cyborg.step(action=action, agent='Red')


def _attempt_exploit(cyborg: CybORG, red_session: int, addr: IPv4Address) \
        -> dict:
    """has red agent attempt to exploit given ip"""
    action = ExploitRemoteService(agent='Red', ip_address=addr,
            session=red_session)
    result = cyborg.step(action=action, agent='Red')

    return result.observation

def _attempt_escalate(cyborg: CybORG, red_session: int, hostname: str) -> dict:
    """has red agent attempt to escalate privileges on given hostname"""
    selector = _dummy_escalate_action_selector

    action  = PrivilegeEscalate(session=red_session, agent='Red', hostname=hostname,
            escalate_action_selector=selector)
    result = cyborg.step(action=action, agent='Red')
    return result.observation

# Run blue remove with no red activity.
def _blue_misinform(cyborg: CybORG, blue_session: int,
        hostname: str, expected_success: bool, is_dummy: bool,*,
        allows_escalate: bool=False, allows_exploit: bool=False,
        sandboxing: bool=False):
    """
    has blue agent attempt to put tomcat or dummy misinform process
    on given hostname
    """
    #print ("hostname: {}, expected_success: {}".format(hostname, expected_success))
    decoy_factory = tomcat_decoy_factory
    if is_dummy:
        decoy_factory = _dummy_escalate_decoy_factory


    decoy_type = DecoyType.NONE
    if not allows_escalate:
        decoy_type = decoy_type | DecoyType.ESCALATE
    if not allows_exploit:
        decoy_type = decoy_type | DecoyType.EXPLOIT
    if sandboxing:
        decoy_type = decoy_type | DecoyType.SANDBOXING_EXPLOIT


    print(f"decoy_type: {decoy_type}")
    blue_action = Misinform(session=blue_session, agent='Blue',
            hostname=hostname)
    results = cyborg.step('Blue', blue_action)
    #print ("observation: {}".format(results.observation))
    assert not results.done
    #assert results.reward == 0
    if expected_success:
        assert results.observation['success'] is TrinaryEnum.TRUE
        non_successes = [v for k,v in results.observation.items() if
                k != 'success']
        #print("non-successes: {}".format(non_successes))
        assert len(non_successes) == 1
        misinforming_host = non_successes[0]
        if is_dummy:
            assert misinforming_host['Processes'][0]['Service Name'] == 'smss'
        else:
            assert misinforming_host['Processes'][0]['Service Name'] == 'tomcat'

    else:
        assert results.observation['success'] is TrinaryEnum.FALSE

def _test_exploit(*, cyborg: CybORG, addresses, red_session, permissive=False):
    # What exploit fails without misinform, due to lack of network access, incompatibility
    exploit_cant_connect = ["Defender", "Enterprise0", "Enterprise1", "Enterprise2",
            "Op_Host0", "Op_Host1", "Op_Host2", "Op_Server0"]
    # What exploit succeeds without misinform
    exploit_would_succeed = ["User0", "User1", "User2", "User3",
            "User4", "User5", "Decoy0", "Decoy1"]
    # What misinform should prevent exploit on
    misinform_exploit_effective = ["User0", "User1", "User2", "User5",
            "Decoy0", "Decoy1"]

    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller
                .hostname_ip_map.items()}[address]
        print (f"Hostname: {hostname}")

        obs = _attempt_exploit(cyborg, red_session, address)
        print (f"Observation: {pprint.pformat(obs)}")
        now_success = obs['success'] is TrinaryEnum.TRUE
        now_fail = obs['success'] is TrinaryEnum.FALSE

        if hostname in exploit_cant_connect:
            assert len(obs.keys()) == 1
            assert now_fail

        elif hostname not in exploit_would_succeed:
            assert now_fail
            assert len(obs.keys()) == 1

        elif not permissive and hostname in misinform_exploit_effective:
            assert now_fail
            print (f"misinform caused exploit to fail: {pprint.pformat(obs)} ")
            assert obs[str(address)]['Processes'][0][ \
                    'Connections'][0]['local_port'] == 443
            assert len(obs.keys()) == 3

        else:
            assert now_success


def _misinform_with_tomcat(cyborg: CybORG, blue_session, *, allows_exploit=False,
        allows_escalate=False):
    # Allow red to successfully exploit these ones
    tomcat_misinform_to_skip = ["User3", "User4"]

    # hosts that misinform tomcat is incompatible with
    incompatible_exploit_hostnames = ["Enterprise1", "Enterprise2"]

    #test misinform failing to apply to incompatible host
    blue_action_space = cyborg.get_action_space('Blue')
    for hostname in blue_action_space['hostname']:
        if hostname in tomcat_misinform_to_skip:
            continue
        will_succeed = hostname not in incompatible_exploit_hostnames
        _blue_misinform(cyborg, blue_session, hostname, will_succeed, False,
                allows_exploit=allows_exploit, allows_escalate=allows_escalate)

def _prep_test_env(seed):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1c.yaml'
    cyborg = CybORG(path, 'sim')
    cyborg.set_seed(seed)

    cyborg.get_observation('Red')
    initial_result_blue = cyborg.get_observation('Blue')
    blue_session = initial_result_blue['Defender']['Sessions'][0]['ID']

    red_action_space = cyborg.get_action_space('Red')
    red_session = list(red_action_space['session'].keys())[0]
    addresses = list(red_action_space["ip_address"])

    return (cyborg, blue_session, red_session, addresses)

@pytest.mark.skip
@pytest.mark.parametrize("seed", [1, 22447, 3242, 4])
def test_blue_misinform_vs_exploit(seed):
    """Tests misinform for interfering with exploit"""
    # Setup Cyborg
    (cyborg, blue_session, red_session, addresses) = _prep_test_env(seed)

    _red_scan(cyborg)

    _misinform_with_tomcat(cyborg, blue_session)

    _red_scan(cyborg)

    _test_exploit(cyborg=cyborg, addresses=addresses, red_session=red_session)

def _misinform_with_dummy(cyborg, blue_session, allows_exploit = False,
        allows_escalate = False, sandboxing=False):
    # dont interfere with user3
    dummy_misinform_to_skip = ["User3"]
    # hosts that misinform dummy is incompatible with
    incompatible_hostnames = ["Enterprise1", "Enterprise2", "User0", "User1",
            "User2", "User5"]

    blue_action_space = cyborg.get_action_space('Blue')
    for hostname in blue_action_space['hostname']:
        if hostname in dummy_misinform_to_skip:
            continue
        will_succeed = hostname not in incompatible_hostnames
        _blue_misinform(cyborg, blue_session, hostname, will_succeed, True,
                allows_exploit=allows_exploit, allows_escalate=allows_escalate,
                sandboxing=sandboxing)

def _test_escalate(*, cyborg: CybORG, addresses, red_session, permissive=False):
    # What escalate succeeds without misinform
    # User0 is already owned, User5 is skipped, User1-4 are exploited successfully
    escalate_would_succeed = ["User0", "User1", "User2", "User3", "User4"]

    # User0 is owned already, User1 - User3 already have smss running
    # User3 was skipped (see _misinform_with_dummy)
    # adversary prefers exploiting smss so decoy works for 4
    misinform_escalate_effective = ["User4"]

    # Decoy0 and Decoy1 are not vulnerable without the decoy, but using permissive mode
    # makes them vulnerable to escalation
    misinform_installed_encountered_not_needed = ["Decoy0", "Decoy1"]

    # Test Escalate
    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller
                .hostname_ip_map.items()}[address]

        print (f"Hostname: {hostname}")
        obs = _attempt_escalate(cyborg, red_session, hostname)
        print (f"Observation: {pprint.pformat(obs)}")

        now_success = obs['success'] is TrinaryEnum.TRUE
        now_fail = obs['success'] is TrinaryEnum.FALSE

        if hostname in misinform_installed_encountered_not_needed:
            if permissive:
                assert now_success
            else:
                assert now_fail

        elif hostname not in escalate_would_succeed:
            assert now_fail

        elif not permissive and hostname in misinform_escalate_effective:
            assert now_fail
            findings = obs.get('User4',None)
            assert findings
            procs = findings.get('Processes',[])
            assert len(procs) == 1
            assert procs[0].get('Process Name',None) == 'smss.exe'

        else:
            assert now_success

@pytest.mark.skip
@pytest.mark.parametrize("seed", [1,2,3,4])
def test_blue_misinform_vs_escalate(seed):
    """
    Tests misinform for interfering with escalate
    """

    (cyborg, blue_session, red_session, addresses) = _prep_test_env(seed)

    _red_scan(cyborg)

    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller
                .hostname_ip_map.items()}[address]

        if hostname != "User5":
            _attempt_exploit(cyborg, red_session, address)

    _misinform_with_dummy(cyborg, blue_session)

    _red_scan(cyborg)

    _test_escalate(cyborg=cyborg, addresses=addresses, red_session=red_session)

@pytest.mark.skip
@pytest.mark.parametrize("seed", [1,2,3,4])
def test_blue_misinform_permit_exploit(seed):
    """
    Tests that decoys can allow exploiting but not escalation
    """

    (cyborg, blue_session, red_session, addresses) = _prep_test_env(seed)

    _red_scan(cyborg)

    _misinform_with_tomcat(cyborg, blue_session, allows_exploit=True)

    _red_scan(cyborg)

    _test_exploit(cyborg=cyborg, addresses=addresses, red_session=red_session,
            permissive=True)

@pytest.mark.skip
@pytest.mark.parametrize("seed", [1,2,3,4])
def test_blue_misinform_permit_escalate(seed):
    """
    Tests that decoys can allow escalation
    """

    (cyborg, blue_session, red_session, addresses) = _prep_test_env(seed)

    _red_scan(cyborg)

    for address in addresses:
        hostname = {v: i for i, v in cyborg.environment_controller
                .hostname_ip_map.items()}[address]

        if hostname != "User5":
            _attempt_exploit(cyborg, red_session, address)

    _misinform_with_dummy(cyborg, blue_session, allows_escalate=True)

    _red_scan(cyborg)

    _test_escalate(cyborg=cyborg, addresses=addresses, red_session=red_session,
            permissive=True)

@pytest.mark.skip
def test_blue_misinform_sandboxing_exploit():
    """
    Tests that decoys can allow escalation
    """

    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    env = CybORG(path,'sim', agents={'Red':B_lineAgent})
    env.reset('Blue')

    for host in ['User1', 'User2']:
        action = Misinform(session=0, agent="Blue", hostname=host)
        env.step(action=action, agent="Blue")

    for _ in range(12):
        env.step()
        action = env.get_last_action('Red')
        success = env.get_observation('Red')['success']

        should_be_failure = isinstance(action, PrivilegeEscalate)
        assert success is not should_be_failure

@pytest.mark.skip
def test_stopping_process_on_priv_esc_on_decoy():
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    env = CybORG(path, 'sim')
    env.set_seed(1)
    subnet = env.get_observation('Red')['User0']['Interface'][0]['Subnet']

    # set up an exploited decoy
    res = env.step('Blue', Misinform(session=0, agent="Blue", hostname='User1'))
    assert res.observation['success'] == True
    res = env.step('Red', DiscoverRemoteSystems(session=0, agent='Red', subnet=subnet))
    assert res.observation['success'] == True
    ip = list(res.observation.values())[2]['Interface'][0]['IP Address']
    res = env.step('Red', DiscoverNetworkServices(session=0, agent='Red', ip_address=ip))
    assert res.observation['success'] == True
    res = env.step('Red', ExploitRemoteService(session=0, agent='Red', ip_address=ip))
    assert res.observation['success'] == True
    session = list(res.observation.values())[2]['Sessions'][0]['ID']
    res = env.step('Red', PrivilegeEscalate(session=0, agent='Red', hostname='User1'))
    assert res.observation['success'] == False

    # test exploited decoy stops running
    assert session not in env.environment_controller.state.sessions['Red']


