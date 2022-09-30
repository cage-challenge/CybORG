# These tests check that the green actions are working:
# DiscoverRemoteSystems, DiscoverNetworkServices, ExploitService, Escalate, Impact

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently
from ipaddress import IPv4Network, IPv4Address

from CybORG import CybORG
import inspect

from CybORG.Shared.Actions.GreenActions.GreenPingSweep import GreenPingSweep
from CybORG.Shared.Actions.AbstractActions.Monitor import Monitor

from CybORG.Shared.Enums import TrinaryEnum, ProcessType, ProcessState, SessionType
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort
import pytest

@pytest.mark.skip("Not implemented")
def test_GreenPingSweep():
    # Create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + '/Shared/Scenarios/Scenario1b.yaml'
    cyborg = CybORG(path, 'sim')

    # Setup Agent
    action_space = cyborg.get_action_space('Green')
    initial_observation = cyborg.get_observation('Green')

    # Test Pingsweep on all knows subnets
    session = 0
    subnets = [i for i in action_space['subnet']]
    for subnet in subnets:
        action = GreenPingSweep(agent='Green', session=session)
        result = cyborg.step(action=action, agent='Green')

        # Blue Monitors the Situation    
        blue_session = cyborg.get_observation('Blue')['Defender']['Sessions'][0]['ID']
        blue_action = Monitor(session=blue_session, agent='Blue')
        results = cyborg.step('Blue', blue_action)                       
                                                          
        expected_result = {'success':TrinaryEnum.TRUE}

        assert result == expected_result

