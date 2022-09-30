import inspect

import pytest

from CybORG import CybORG


@pytest.fixture(scope="function", params=['Scenario1', 'Scenario1b'])
def create_cyborg_sim(request):
    path = str(inspect.getfile(CybORG))
    path = path[:-10] + f'/Shared/Scenarios/{request.param}.yaml'
    cyborg = CybORG(path, 'sim')
    return cyborg, request.param

# TODO add in autouse cyborg reset function
