# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation

from .AgentAction import AgentAction


class CreateSession(AgentAction):
    """Create a new session on Team server for given game and agent.

    This session is designed for terminal commands executed on team server
    machine that affect a single game.

    Parameters
    ----------
    session_handler_cls : SessionHandler
        the session handler class to use for session
    handler_kwargs : dict, optional
        keyword arguments that will be passed to the session (default=None)
    """

    def __init__(self, session_handler_cls, handler_kwargs: dict = None):
        super().__init__()
        self.session_handler_cls = session_handler_cls
        self.handler_kwargs = {} if handler_kwargs is None else handler_kwargs

    def emu_execute(self, agent, *args, **kwargs) -> Observation:
        self._log_debug(f"Executing action: {self}")
        session_handler = self.session_handler_cls.create_new_session(
            **self.handler_kwargs
        )
        agent.add_session(session_handler)
        obs = Observation()
        obs.set_success(True)
        obs.add_session_info(agent=agent.agent_name,
                             **session_handler.get_info())
        return obs

    def __str__(self):
        return (f"{self.__class__.__name__}: "
                f"SessionHandler: {self.session_handler_cls.__name__}"
                f"kwargs: {self.handler_kwargs}")
