import enum
from ipaddress import IPv4Address

import yaml

from CybORG import CybORG
from CybORG.Emulator.AWS import AWSConfig


def enum_representer(dumper, data):
    return dumper.represent_scalar(u'tag:yaml.org,2002:str', f'{str(data.name)}')


def ipv4_representer(dumper, data):
    return dumper.represent_scalar(u'tag:yaml.org,2002:str', f'{str(data)}')


yaml.add_multi_representer(enum.Enum, enum_representer)
yaml.add_representer(IPv4Address, ipv4_representer)

scenario = '/home/max/PycharmProjects/Autonomous-Cyber-Ops/CybORG/Shared/Scenarios/SingleHostScenario.yaml'
image = "Velociraptor_Server"
sm = {'Hosts': {'Test_Host': {'image': image}}}
cyborg = CybORG(scenario, environment='aws', env_config={
    "config": AWSConfig.load_and_setup_logger(test=True),
    "create_tunnel": False
})
try:
    info_required = {'Test_Host': {'User_info': 'All',
                                  'System_info': 'All',
                                  'Processes': 'All',
                                  'Files': ['/root', '/bin', '/sbin', '/etc', '/home', '/usr/sbin/', '/usr/bin/']}}
    true_state = cyborg.get_true_state(info_required)
    true_state.data.pop('success')
    assert true_state.data != {}
    for key, data in true_state.data.items():
        if "Interface" in data:
            data.pop("Interface")
        if 'Processes' in data:
            for proc in data['Processes']:
                if 'Known Process' in proc:
                    proc.pop('Known Process')
                if 'Known Path' in proc:
                    proc.pop('Known Path')
        if 'System info' in data and 'Hostname' in data['System info']:
            data['System info'].pop('Hostname')
        if 'User Info' in data:
            for user in data['User Info']:
                if 'Groups' in user:
                    for group in user['Groups']:
                        if 'Builtin Group' in group:
                            group.pop('Builtin Group')
    print(true_state)
    with open(f'{image}_image.yaml', 'w') as outfile:
        yaml.dump(true_state.data, outfile, default_flow_style=False)
finally:
    cyborg.shutdown(teardown=True)
