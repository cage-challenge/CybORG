# import inspect
# import random
# from CybORG import CybORG
# from CybORG.Agents import RedMeanderAgent, B_lineAgent
# from CybORG.Agents.Wrappers import ChallengeWrapper
# from CybORG.Shared.Actions import Remove

# path = str(inspect.getfile(CybORG))
# path = path[:-10] + '/Shared/Scenarios/Scenario2.yaml'
# agents = {'Red':RedMeanderAgent}
# # agents = {'Red': B_lineAgent}
# cyborg = CybORG(path, 'sim', agents=agents)
# env = ChallengeWrapper(env=cyborg, agent_name='Blue')

# obs = env.reset()

# for ep in range(1000):
    # obs = env.reset()
    # history = []
    # for step in range(50):
        # action = env.action_space.sample()
        # # action = 0
        # obs, reward, done, info = env.step(action)

        # red_action = env.get_last_action('Red')
        # history.append(red_action)
        # # print(env.get_last_action('Red'))

        # if 'Invalid' in env.get_last_action('Red').__class__.__name__:
            # from pprint import pprint
            # controller = env.get_attr('environment_controller')
            # agent = controller.agent_interfaces['Red'].agent
            # ips = agent.exploited_ips
            # hosts = agent.escalated_hosts
            # ip_map = agent.host_ip_map
            # breakpoint()
            # 'Invalid Action'

    # print(ep)
    # print(env.get_last_action('Red'))
