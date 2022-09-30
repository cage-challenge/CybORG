import inspect
# allows import of CybORG class as:
# from CybORG import CybORG
from CybORG.env import CybORG

path = str(inspect.getfile(CybORG))
path = path[:-7] + '/version.txt'
with open(path) as f:
    CYBORG_VERSION = f.read()[:-1]
