

from CybORG.Shared import Observation
from .Monitor import Monitor
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.ConcreteActions.RestoreFromBackup import RestoreFromBackup
from CybORG.Simulator.Session import VelociraptorServer
from CybORG.Simulator.Actions.AbstractActions import Monitor

class Restore(Action):
    def __init__(self, session: int, agent: str, hostname: str):
        super().__init__()
        self.agent = agent
        self.session = session
        self.hostname = hostname

    def execute(self, state) -> Observation:
        # perform monitor at start of action
        #monitor = Monitor(session=self.session, agent=self.agent)
        #obs = monitor.execute(state)

        if self.session not in state.sessions[self.agent]:
            return Observation(False)
        parent_session: VelociraptorServer = state.sessions[self.agent][self.session]
        # find relevant session on the chosen host
        sessions = [s for s in state.sessions[self.agent].values() if s.hostname == self.hostname]
        if len(sessions) > 0:
            session = state.np_random.choice(sessions)
            obs = Observation(True)
            # restore host
            action = RestoreFromBackup(session=self.session, agent=self.agent, target_session=session.ident)
            action.execute(state)
            # remove suspicious files
            return obs
        else:
            return Observation(False)

    @property
    def cost(self):
        return -1

    def __str__(self):
        return f"{self.__class__.__name__} {self.hostname}"
