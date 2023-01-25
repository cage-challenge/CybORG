
from typing import Tuple, List
from ipaddress import IPv4Address

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.ConcreteActions.EscalateActions.EscalateAction import EscalateAction, ExploreHost
from CybORG.Simulator.Actions.ConcreteActions.LocalAction import LocalAction
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions, \
    RemoveOtherSessions_AlwaysSuccessful
from CybORG.Shared.Enums import TrinaryEnum, DecoyType, OperatingSystemType, SessionType
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process
from CybORG.Simulator.State import State
from CybORG.Simulator.Session import Session


class SeizeControl(LocalAction):
    """
    Implements a privilege escalation action on a drone host
    Also kills any hostile teams session
    """

    def __init__(self, ip_address: IPv4Address, session: int, agent: str):
        super().__init__(session, agent)
        self.ip_address = ip_address
        self.priority = 10

    def execute(self, state: State) -> Observation:
        if self.session not in state.sessions[self.agent]:
            return Observation(False)
        # find session on the chosen host
        hostname = state.ip_addresses[self.ip_address]
        target_host = state.hosts[hostname]
        sessions = [s for s in state.sessions[self.agent].values() if s.hostname == hostname]
        if len(sessions) == 0:
            # no valid session could be found on chosen host
            obs = Observation(success=False)
            obs.add_raw_obs('No valid session')
            return obs

        # find if any session are already SYSTEM or root
        target_session = None
        obs = Observation(False)
        obs.add_raw_obs('Default Failure of action')
        for sess in sessions:
            # else find if session is Admin or sudo
            if sess.username in ('root', 'SYSTEM'):
                target_session = sess
                obs.set_success(True)
                obs.add_session_info(hostid=hostname, **sess.get_state())
                break
        # else use random session
        if target_session is None:
            target_session = state.np_random.choice(sessions)
            is_compatible = self.test_exploit_works(target_host)
            if not is_compatible:
                obs.set_success(False)
                obs.add_raw_obs('Exploit not compatible')
                return obs
            necessary_processes = self.get_necessary_processes(target_host)
            if necessary_processes is not None:
                for proc in necessary_processes:
                    if proc.decoy_type & DecoyType.ESCALATE:
                        obs.set_success(False)
                        obs.add_process(hostid=target_host.hostname, process_name=proc.name)
                        obs.add_raw_obs('Fell for Decoy')
                        return obs

            ext = 'sh'
            path = '/tmp/'
            # upgrade session to new username
            target_session.username = "root"
            # determine new agent name from hostname and acting agent
            target_session.agent = '_'.join(self.agent.split('_')[:-1]) + '_' + hostname.split('_')[-1]
            state.sessions[target_session.agent][0] = state.sessions[self.agent].pop(target_session.ident)
            # if target_session.ident in state.sessions[self.agent][0].children:
            #     state.sessions[self.agent][0].children.pop(target_session.ident)
            if target_session.ident in state.sessions[self.agent][self.session].children:
                state.sessions[self.agent][self.session].children.pop(target_session.ident)
            target_session.parent = None
            target_host.sessions[self.agent].remove(target_session.ident)
            target_session.ident = 0
            if 0 not in target_host.sessions[target_session.agent]:
                state.sessions_count[target_session.agent] += 1
                target_host.sessions[target_session.agent].append(target_session.ident)
                target_host.get_process(target_session.pid).user = "root"
                if 'red' in self.agent:
                    session_type = SessionType.RED_DRONE_SESSION
                elif 'blue' in self.agent:
                    session_type = SessionType.BLUE_DRONE_SESSION
                else:
                    session_type = target_session.session_type
                target_session.session_type = session_type
                target_host.add_file(f'escalate.{ext}', path, "root", 7,
                        density=0.9, signed=False)
            obs.set_success(True)
        if obs.data['success'] is not TrinaryEnum.TRUE:
            return obs

        sub_action = RemoveOtherSessions_AlwaysSuccessful(session=target_session.ident, agent=target_session.agent, level='privileged')
        sub_action.execute(state)
        return obs

    def test_exploit_works(self, target_host: Host) -> bool:
        return True

    def get_necessary_processes(self, target_host: Host) -> Tuple[Process, ...]:
        return None
