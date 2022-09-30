from CybORG.Shared import Observation
from CybORG.Shared.Actions.ConcreteActions.ConcreteAction import ConcreteAction
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process
from CybORG.Simulator.State import State


class RestoreFromBackup(ConcreteAction):
    def __init__(self, session: int, agent: str, target_session: int):
        super(RestoreFromBackup, self).__init__(session, agent)
        self.target_session = target_session

    def sim_execute(self, state: State) -> Observation:
        obs = Observation()
        if self.session not in state.sessions[self.agent] or self.target_session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        target_host: Host = state.hosts[state.sessions[self.agent][self.target_session].host]
        session = state.sessions[self.agent][self.session]
        target_session = state.sessions[self.agent][self.target_session]

        if not session.active or not target_session.active:
            obs.set_success(False)
            return obs

        old_sessions = {}
        for agent, sessions in target_host.sessions.items():
            old_sessions[agent] = {}
            for session in sessions:
                old_sessions[agent][session] = state.sessions[agent].pop(session)
        target_host.restore()
        for agent, sessions in target_host.sessions.items():
            for session in sessions:
                state.sessions[agent][session] = old_sessions[agent][session]
        return obs
