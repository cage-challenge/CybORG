## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.

"""
pertaining to actions that escalate a session on a host, or occur failing that
"""
# pylint: disable=invalid-name

from abc import abstractmethod
from typing import Tuple

from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ConcreteAction import ConcreteAction
from CybORG.Shared.Enums import OperatingSystemType, DecoyType
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process
from CybORG.Simulator.Session import Session
from CybORG.Simulator.State import State

class EscalateAction(ConcreteAction):
    """
    base class for actions that escalate a session on a host
    """
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session, agent)
        self.state = None
        self.target_session = target_session

    def emu_execute(self) -> Observation:
        raise NotImplementedError

    def sim_escalate(self, state: State, user: str) -> Observation:
        """
        escalate the session on the host if it works
        """
        self.state = state
        obs = Observation()
        if (self.session not in state.sessions[self.agent]
                or self.target_session not in state.sessions[self.agent]):
            obs.set_success(False)
            return obs
        target_host = state.hosts[state.sessions[self.agent][self.target_session].host]
        session = state.sessions[self.agent][self.session]
        target_session = state.sessions[self.agent][self.target_session]

        if not session.active or not target_session.active:
            obs.set_success(False)
            return obs

        is_compatible, necessary_processes = self.test_exploit_works(target_host)
        if not is_compatible:
            obs.set_success(False)
            return obs

        for proc in necessary_processes:
            if proc.decoy_type & DecoyType.ESCALATE:
                obs.set_success(False)
                obs.add_process(hostid=target_host.hostname, process_name=proc.name)
                return obs

        obs = self.__upgrade_session(user, target_host, target_session)
        return obs

    @abstractmethod
    def test_exploit_works(self, target_host: Host) ->\
            Tuple[bool, Tuple[Process, ...]]:
        """
        checks if OS and process information is correct for escalate to work.
        First return is True if compatible, False otherwise.
        Second return is tuple of all processes which must be valid for escalate to succeed.
        """
        raise NotImplementedError

    def __upgrade_session(self, username: str, target_host: Host, session: Session):
        """
        called when successful, upgrades the session privileges
        """
        if target_host.os_type == OperatingSystemType.WINDOWS:
            ext = 'exe'
            path = 'C:\\temp\\'
        elif target_host.os_type == OperatingSystemType.LINUX:
            ext = 'sh'
            path = '/tmp/'
        else:
            return Observation(False)
        obs = Observation()
        # upgrade session to new username
        session.username = username
        target_host.get_process(session.pid).user = username
        target_host.add_file(f'escalate.{ext}', path, username, 7,
                density=0.9, signed=False)
        # add in new session info to observation
        obs.add_session_info(hostid=str(target_host.hostname),
                             session_id=session.ident,
                             session_type=session.session_type,
                             username=username,
                             agent=self.agent)
        obs.set_success(True)
        return obs


class ExploreHost(ConcreteAction):
    """Gets information on host"""
    def __init__(self, session: int, agent: str, target_session: int):
        super().__init__(session, agent)
        self.target_session = target_session

    def emu_execute(self) -> Observation:
        raise NotImplementedError

    def sim_execute(self, state: State) -> Observation:
        if (self.session not in state.sessions[self.agent]
                or self.target_session not in state.sessions[self.agent]):
            return Observation(success=False)
        target_host = state.hosts[state.sessions[self.agent][self.target_session].host]
        obs = state.get_true_state(target_host.info)
        obs.set_success(True)
        return obs
