from CybORG import CybORG
from CybORG.Agents.SimpleAgents.B_line import B_lineAgent
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator


sg = DroneSwarmScenarioGenerator()
cyborg = CybORG(sg, 'sim')

red_agent = B_lineAgent()
cyborg = CybORG(sg, 'sim', agents={'Red': red_agent})

print('Starting simulation')