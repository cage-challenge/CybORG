# Copyright DST Group. Licensed under the MIT license.
from CybORG.Shared import Observation
from CybORG.Shared.Enums import QueryType

from .VelociraptorAction import VelociraptorAction


class VelociraptorArtifactAction(VelociraptorAction):

    def __init__(self,
                 session: int,
                 hostname: str,
                 agent: str,
                 artifact: str,
                 env: dict = None,
                 flow_completion_wait_limit: int = 60,
                 query_type: QueryType = QueryType.ASYNC):
        super().__init__(session=session,
                         agent=agent,
                         query_type=query_type,
                         hostname=hostname,
                         poll_alerts=True)
        self.artifact = artifact
        self.flow_completion_wait_limit = flow_completion_wait_limit

        if env is None:
            env = {
                "agentid": agent,
                "artifactname": artifact,
                "tag": agent
            }
        self.env = env

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
        vel_controller = session_handler.controller
        client_id = vel_controller.get_client_id_for_hostname(self.hostname)

        results = vel_controller.execute_flow(
            client_id=client_id,
            artifact=self.artifact,
            env=self.env,
            completion_wait_limit=self.flow_completion_wait_limit
        )

        # Aren't getting the expected list in results, which results in exception


        obs = self.parse(results, client_id)

        if self.poll_alerts:
            obs = vel_controller.get_latest_alerts(obs)

        return obs

    def parse(self, results: list, client_id: str) -> Observation:
        """Parses the results of the execute action to create an observation"""
        raise NotImplementedError
