from ipaddress import IPv4Address, IPv4Network
from copy import deepcopy
from collections import namedtuple

import pytest

from CybORG.Simulator.Actions import (DiscoverRemoteSystems, DiscoverNetworkServices, ExploitRemoteService, 
        PrivilegeEscalate, Impact)

from CybORG.Shared.Enums import (TrinaryEnum, ProcessType, ProcessState, SessionType, OperatingSystemType, 
        OperatingSystemDistribution, OperatingSystemVersion, Architecture)

# All the following Observations are obtained from Scenario 1b on CybORG v2.0

OBS_SUCCESS = {'success':TrinaryEnum.TRUE}
OBS_FAIL = {'success':TrinaryEnum.FALSE}

##########################################################################################

SUBNET = IPv4Network('10.0.33.64/28')
SOURCE_HOST = 'User0'
SOURCE_IP = IPv4Address('10.0.33.68')
TARGET_HOST = 'User1'
TARGET_IP = IPv4Address('10.0.33.73')
ENTERPRISE_HOST = 'Enterprise1'
ENTERPRISE_IP = IPv4Address('10.0.109.210')
##########################################################################################


INITIAL_INTERFACE = {
        'Interface Name': 'eth0',
        'IP Address': SOURCE_IP,
        'Subnet': SUBNET
        }

INITIAL_SESSION = {
        'Username': 'SYSTEM',
        'ID': 0,
        'Timeout': 0,
        'PID': 2014,
        'Type': SessionType.RED_ABSTRACT_SESSION,
        'Agent': 'Red'
        }

INITIAL_PROCESS = {
        'PID': 2014,
        'Username': 'SYSTEM'
        }

INITIAL_OS = {
        'Hostname': SOURCE_HOST,
        'OSType': OperatingSystemType.WINDOWS,
        'OSDistribution': OperatingSystemDistribution.WINDOWS_SVR_2008,
        'OSVersion': OperatingSystemVersion.W6_1_7601,
        'Architecture': Architecture.x64
        }

RED_INITIAL = {
        'success': TrinaryEnum.UNKNOWN,
        'User0': {
            'Interface': [INITIAL_INTERFACE],
            'Sessions': [INITIAL_SESSION],
            'Processes': [INITIAL_PROCESS],
            'System info': INITIAL_OS
            }
        }

##########################################################################################

RED_PINGSWEEP = {
    'success': TrinaryEnum.TRUE,
    str(SOURCE_IP): {'Interface': [{'IP Address': IPv4Address('10.0.33.68'), 'Subnet': IPv4Network('10.0.33.64/28')}]},
    str(TARGET_IP): {'Interface': [{'IP Address': IPv4Address('10.0.33.73'), 'Subnet': IPv4Network('10.0.33.64/28')}]},
    '10.0.33.66': {'Interface': [{'IP Address': IPv4Address('10.0.33.66'), 'Subnet': IPv4Network('10.0.33.64/28')}]},
    '10.0.33.74': {'Interface': [{'IP Address': IPv4Address('10.0.33.74'), 'Subnet': IPv4Network('10.0.33.64/28')}]},
    '10.0.33.78': {'Interface': [{'IP Address': IPv4Address('10.0.33.78'), 'Subnet': IPv4Network('10.0.33.64/28')}]}
    }

SUBNET_IPS = [IPv4Address(k) for k in RED_PINGSWEEP if k!='success']
##########################################################################################

PORTSCAN_CONNECTIONS = [
        {'Connections': [{'local_port': 22, 'local_address': TARGET_IP}]},
        {'Connections': [{'local_port': 21, 'local_address': TARGET_IP}]}
        ]

RED_PORTSCAN = {
    'success': TrinaryEnum.TRUE,
    '10.0.33.73': {
        'Processes': PORTSCAN_CONNECTIONS, 
        'Interface': [{'IP Address': TARGET_IP}]
        }
    }

EXPLOIT_HANDLER = {
    'Connections': [{
        'local_port': 4444,
        'remote_port': 55701,
        'local_address': SOURCE_IP,
        'remote_address': TARGET_IP
        }],
    'Process Type': ProcessType.REVERSE_SESSION_HANDLER
    }

EXPLOIT_SHELL = {
    'Connections': [{
        'local_port': 55701,
        'remote_port': 4444,
        'local_address': TARGET_IP,
        'remote_address': SOURCE_IP
        }], 
    'Process Type': ProcessType.REVERSE_SESSION
    }

EXPLOIT_PAYLOAD = {
        'Connections': [{
            'local_port': 21,
            'local_address': TARGET_IP,
            'Status': ProcessState.OPEN
            }]
        }

EXPLOIT_SESSION = {
    'ID': 1,
    'Type': SessionType.RED_REVERSE_SHELL,
    'Agent': 'Red'
    }

EXPLOIT_OS = {
    'Hostname': TARGET_HOST,
    'OSType': OperatingSystemType.WINDOWS
    }

RED_EXPLOIT = {
    'success': TrinaryEnum.TRUE,
    SOURCE_IP: {
        'Processes': [EXPLOIT_HANDLER],
        'Interface': [{'IP Address': SOURCE_IP}]},
    TARGET_IP: {
        'Processes': [EXPLOIT_PAYLOAD, EXPLOIT_SHELL],
        'Process Type': ProcessType.FEMITTER,
        'Interface': [{'IP Address': TARGET_IP}],
        'Sessions': [EXPLOIT_SESSION],
        'System info': EXPLOIT_OS}
}

##########################################################################################

PRIVESC_INTERFACE = {
        'Interface Name': 'eth0',
        'IP Address': TARGET_IP,
        'Subnet': SUBNET
        }

PRIVESC_SESSION = {
        'Username': 'SYSTEM',
        'ID': 1,
        'Timeout': 0,
        'PID': 22129,
        'Type': SessionType.RED_REVERSE_SHELL,
        'Agent': 'Red'
        }

PRIVESC_PROCESS = {
        'PID': 22129,
        'Username': 'SYSTEM'
        }

RED_PRIVESC = {
        'success': TrinaryEnum.TRUE, 
        TARGET_HOST: {
            'Sessions': [PRIVESC_SESSION],
            'Processes': [PRIVESC_PROCESS],
            'Interface': [PRIVESC_SESSION]
            },
        ENTERPRISE_HOST: {
                'Interface': [{'IP Address': ENTERPRISE_IP}]
                }
        }

##########################################################################################

ObsTuple = namedtuple('ObsTuple',['obs','action'])

PARAMS = {'session':0, 'agent':'Red'}

RED_OBS_DICT = {
        'RED_INITIAL': ObsTuple(RED_INITIAL, None),
        'RED_PINGSWEEP': ObsTuple(RED_PINGSWEEP, DiscoverRemoteSystems(SUBNET, **PARAMS)),
        'RED_PORTSCAN': ObsTuple(RED_PORTSCAN, DiscoverNetworkServices(ip_address=TARGET_IP, **PARAMS)),
        'RED_EXPLOIT': ObsTuple(RED_EXPLOIT, ExploitRemoteService(TARGET_IP, **PARAMS)),
        'RED_PRIVESC': ObsTuple(RED_PRIVESC, PrivilegeEscalate(TARGET_HOST, **PARAMS)),
        'OBS_SUCCESS': ObsTuple(OBS_SUCCESS, Impact(TARGET_HOST, **PARAMS)),    # Not Op_Server for testing purposes
        'OBS_FAIL': ObsTuple(OBS_FAIL, None),
        }

OBS_NAMES = RED_OBS_DICT.keys()
RED_OBSERVATIONS = [t.obs for t in RED_OBS_DICT.values()]
RED_ACTIONS = [t.action for t in RED_OBS_DICT.values() if t.action is not None]

