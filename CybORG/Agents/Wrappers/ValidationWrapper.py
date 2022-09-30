from CybORG.Agents.Wrappers import BaseWrapper


class ValidationDroneWrapper(BaseWrapper):
    def __init__(self, env):
        super().__init__(env)
        self.num_agents = len(env.active_agents)
        assert not env.scenario_generator.red_internal_only, "This test requires that the red_internal_only=False flag is set"

    def step(self, agent=None, action=None):
        out = super(ValidationDroneWrapper, self).step(agent, action)
        # assert that there is only ever either a blue or red agent per drone
        for a in self.env.active_agents:
            for b in self.env.active_agents:
                if a != b:
                    assert a.split('_')[-1] != b.split('_')[-1], f'{a}, {b}'
        # assert that blue agents only ever have 1 session
        for a in self.env.environment_controller.state.sessions:
            if 'blue' in a:
                assert len(self.env.environment_controller.state.sessions[a]) < 2
        # ensure that there are the same number of active agents
        assert len(self.env.active_agents) == self.num_agents, f"There are currently {len(self.env.active_agents)}, there were {self.num_agents} " \
                                                               f"the missing agents are {['agent_' + str(i) for i in range(self.num_agents) if 'blue_agent_'+ str(i) not in self.env.active_agents and 'red_agent_'+ str(i) not in self.env.active_agents]}"
        return out

    def reset(self, agent=None, seed=None):
        out = super(ValidationDroneWrapper, self).reset(agent, seed)
        for a in self.env.active_agents:
            for b in self.env.active_agents:
                if a != b:
                    assert a.split('_')[-1] != b.split('_')[-1]
        self.num_agents = len(self.env.active_agents)
        return out
