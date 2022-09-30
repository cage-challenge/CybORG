# These tests check that the green actions are working:
# DiscoverRemoteSystems, DiscoverNetworkServices, ExploitService, Escalate, Impact

# tests need to check that a range of inputs result in the correct changes to the state and return the correct obs
# tests should establish varying environmental states that results in these actions performing differently
from ipaddress import IPv4Network, IPv4Address

from CybORG import CybORG
import inspect

from CybORG.Agents.SimpleAgents.GreenAgent import GreenAgent

from CybORG.Shared.Enums import TrinaryEnum, ProcessType, ProcessState, SessionType
from CybORG.Simulator.Scenarios.FileReaderScenarioGenerator import FileReaderScenarioGenerator
from CybORG.Tests.EphemeralPort import Win2008EphemeralPort
import pytest

def test_GreenAgent():
    # Create cyborg environment
    path = str(inspect.getfile(CybORG))
    path = path[:-7] + f'/Simulator/Scenarios/scenario_files/Scenario1b.yaml'
    sg = FileReaderScenarioGenerator(path)
    cyborg = CybORG(scenario_generator=sg, agents={'Green': GreenAgent()})

    # Setup Agent
    action_space = cyborg.get_action_space('Green')
    session = action_space['session']
    assert session

