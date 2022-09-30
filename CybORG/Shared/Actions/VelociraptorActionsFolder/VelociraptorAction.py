# Copyright DST Group. Licensed under the MIT license.

from CybORG.Shared import Observation
from CybORG.Shared.Enums import QueryType

from .HostMonitoringAction import HostMonitoringAction


class VelociraptorAction(HostMonitoringAction):

    def __init__(self,
                 session: int,
                 agent: str,
                 query_type: QueryType,
                 hostname: str = None,
                 poll_alerts: bool = True):
        super().__init__(session=session)
        self.agent = agent
        self.hostname = hostname
        self.parameters = {'agentid': agent}
        self.query_type = query_type
        self.query = ''
        self.source_query = ''
        self.poll_alerts = poll_alerts

    def emu_execute(self,
                    session_handler,
                    *args,
                    **kwargs) -> Observation:
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

        if self.hostname is None:
            client_id = None
        else:
            client_id = vel_controller.get_client_id_for_hostname(
                self.hostname
            )

        self.query = self.update_params(self.query, client_id)
        self.source_query = self.update_params(
            #            self.source_query, session_handler.controller
            self.source_query, client_id
        )
        results = vel_controller.execute_vql_query(
            query_name=self.name,
            query=self.query,
        )

        self.debug(f"results={results}")

        obs = self.parse(results, client_id)

        if self.poll_alerts:
            obs = vel_controller.get_latest_alerts(obs)

        return obs

    def parse(self, results: list, client_id: str) -> Observation:
        """Parses the results of the execute action to create an observation"""
        raise NotImplementedError

    def update_params(self, query: str, client_id: str):
        if '<agent_name>' in query:
            query = query.replace('<agent_name>', self.agent)
        if '<host_id>' in query:
            query = query.replace('<host_id>', client_id)
        if '<process>' in query:
            query = query.replace('<process>', self.process)
        if '<process_name>' in query:
            query = query.replace('<process_name>', self.process_name)
        if '<username>' in query:
            query = query.replace('<username>', self.username)
        if '<agentid>' in query:
            query = query.replace('<agent_id>', self.agent)
        if '<artifactname>' in query:
            if 'artifactname' in self.parameters:
                artifact = self.parameters['artifactname']
                query = query.replace('<artifactname>', artifact)
            else:
                query = query.replace("artifactname = '<artifactname>', ", "")
        if '<tag>' in query:
            if 'tag' in self.parameters:
                query = query.replace('<tag>', self.parameters['tag'])
            else:
                query = query.replace("tag = '<tag>'", "")

        return query

    def __str__(self):
        return super(VelociraptorAction, self).__str__() + f", {self.hostname}"
