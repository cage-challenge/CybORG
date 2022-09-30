from CybORG.Shared import Observation
from CybORG.Shared.Actions import Action
from CybORG.Simulator.Session import VelociraptorServer
from CybORG.Simulator.State import State


class Monitor(Action):
    def __init__(self, session: int, agent: str):
        super().__init__()
        self.agent = agent
        self.session = session

    def sim_execute(self, state: State) -> Observation:
        obs = Observation(True)
        session: VelociraptorServer = state.sessions[self.agent][self.session]
        for child in session.children.values():
            for artifact in session.artifacts:
                if len(state.hosts[child.host].events[artifact]) > 0:
                    obs.add_system_info(hostid=child.host, **state.hosts[child.host].get_state())
                for event in state.hosts[child.host].events[artifact]:
                    if 'pid' in event:
                        session.add_sus_pids(hostname=child.host, pid=event['pid'])
                    obs.add_process(hostid=child.host, **event)
                state.hosts[child.host].events[artifact] = []
        return obs

    def __str__(self):
        return f"{self.__class__.__name__}"
