from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.ConcreteActions.RemoveOtherSessions import RemoveOtherSessions_AlwaysSuccessful
from CybORG.Simulator.State import State


class ActivateTrojan(Action):
    def __init__(self, agent, hostname: str):
        super().__init__()
        self.hostname = hostname
        self.agent = agent

    def execute(self, state: State) -> Observation:
        if self.hostname in state.hosts:
            host = state.hosts[self.hostname]
            # create new root session
            agent = 'red_agent_' + self.hostname.split('_')[-1]
            session = state.add_session(self.hostname, 'root', agent, None, session_type="red_drone_session", ident=0)
            # remove other sessions
            sub_action = RemoveOtherSessions_AlwaysSuccessful(session.ident, agent, level='privileged')
            return sub_action.execute(state)
        else:
            return Observation(False)
