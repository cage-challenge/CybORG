from CybORG.Simulator.Actions import Action


class LocalAction(Action):
    """
    Abstract class for all concrete actions that occur locally on a host
    """
    def __init__(self,session: int,agent: str):
        super().__init__()
        self.agent = agent
        self.session = session

    def check_for_enterprise_sessions(self, state):
        permission = False
        for session_id in state.sessions[self.agent]:
            session = state.sessions[self.agent][session_id]
            if 'Enterprise' in session.hostname:
                permission = True

        return permission


