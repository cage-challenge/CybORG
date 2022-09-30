from CybORG import CybORG
import inspect


# Set up CybORG
print("Setup")
path = str(inspect.getfile(CybORG))
path = path[:-10] + '/Shared/Scenarios/Scenario1KeyboardBlue.yaml' # Change this to pick your agents
cyborg = CybORG(path, 'sim')

for i in range(1):
    print(f"Game: {i}")
    cyborg.start(1000)
    cyborg.reset()

