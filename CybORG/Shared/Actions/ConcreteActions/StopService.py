from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ConcreteAction import ConcreteAction
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Session import Session, RedAbstractSession
from CybORG.Simulator.State import State


class StopService(ConcreteAction):
    def __init__(self, agent: str, session: int, target_session: int, service: str):
        super().__init__(session, agent)
        self.service = service
        self.target_session = target_session

    def sim_execute(self, state: State):
        # check that both sessions exist
        if self.session not in state.sessions[self.agent] or self.target_session not in state.sessions[self.agent]:
            return Observation(False)

        # check that both sessions are active
        parent_session: RedAbstractSession = state.sessions[self.agent][self.session]
        client_session: Session = state.sessions[self.agent][self.target_session]
        if not parent_session.active or not client_session.active:
            return Observation(False)

        # get target host
        target_host: Host = state.hosts[client_session.host]
        # find chosen service on host
        if self.service not in target_host.services:
            return Observation(False)
        service = target_host.services[self.service]
        state.stop_service(target_host.hostname, self.service)
        obs = Observation(True)

        return obs
