# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions.SessionAction import SessionAction


class ShellAction(SessionAction):
    """Abstract class for a shell action.

    A session action is one that operates within the context of a single
    scenario/game instance in a single shell session.

    Parameters
    ----------
    session : int
        the id of the session to perform action in
    agent : str, optional
        the id of the agent performing the action (default=None)
    """

    def __init__(self, session: int, agent: str = None):
        super().__init__(session)
        self.agent = agent
