from random import choice

from CybORG.Shared import Observation
from .Monitor import Monitor
from CybORG.Shared.Actions import Action
from CybORG.Shared.Actions.AbstractActions import Monitor
from CybORG.Shared.Actions.ConcreteActions.DensityScout import DensityScout
from CybORG.Shared.Actions.ConcreteActions.SigCheck import SigCheck


class Analyse(Action):
    def __init__(self, session: int, agent: str, hostname: str):
        super().__init__()
        self.agent = agent
        self.session = session
        self.hostname = hostname

    def sim_execute(self, state) -> Observation:
        # perform monitor at start of action
        #monitor = Monitor(session=self.session, agent=self.agent)
        #obs = monitor.sim_execute(state)
        
        artefacts = [DensityScout, SigCheck]
        # find relevant session on the chosen host
        sessions = [s for s in state.sessions[self.agent].values() if s.host == self.hostname]
        if len(sessions) > 0:
            session = choice(sessions)
            # run the artifacts on the chosen host
            obs = Observation(True)
            for artifact in artefacts:
                sub_action = artifact(agent=self.agent, session=self.session, target_session=session.ident)
                sub_obs = sub_action.sim_execute(state)
                obs.combine_obs(sub_obs)
            return obs
        else:
            return Observation(False)
    def __str__(self):
        return f"{self.__class__.__name__} {self.hostname}"
    
