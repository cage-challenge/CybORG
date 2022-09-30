# Copyright DST Group. Licensed under the MIT license.
from .Action import Action


class SessionAction(Action):
    """Abstract class for a session level action.

    A session action is one that operates within the context of a single
    scenario/game instance in a single session.

    Note, here a session does not necessarily mean a remote SSH session,
    it may be a velociraptor session, Metasploit API session, etc

    Parameters
    ----------
    session : int
        the id of the session to perform action in
    """

    def __init__(self, session: int):
        """
        Parameters
        ----------
        session : int
            the id of the session to perform action in
        """
        super().__init__()
        self.session = session

    def emu_execute(self, session_handler):
        """Execute and action in emulator environment

        Parameters
        ----------
        session_handler : SessionHandler
           session handler object for game session of action (i.e. that
           matches session_id)

        Returns
        -------
        Observation
            Result of performing action
        """
        raise NotImplementedError

    def sim_execute(self, state):
        raise NotImplementedError

    def __str__(self):
        return (f"{self.__class__.__name__}: Session={self.session}")
