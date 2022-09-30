# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared.Actions import SessionAction
from CybORG.Shared import Observation


class HostMonitoringAction(SessionAction):
    """Abstract class for a host monitoring action. """

    def __init__(self, session: int):
        """
        Parameters
        ----------
        session : int
            the id of the session to perform action in
        """
        super().__init__(session)
        self.name = self.__class__.__name__

    def emu_execute(self,
                    session_handler,
                    *args,
                    **kwargs):
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

    def parse(self, results) -> Observation:
        """Parses the results of the execute action to create an observation"""
        raise NotImplementedError

    def sim_execute(self, state):
        raise NotImplementedError
