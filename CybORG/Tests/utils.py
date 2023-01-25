import copy

import numpy as np


class PID:
    def __eq__(self, other):
        if issubclass(type(other), PID):
            return True
        if type(other) is int:
            return True
        return False


def compare_fundamental_observations(obs1: dict, obs2: dict, translation: dict):
    assert type(obs1) is dict
    assert type(obs2) is dict
    # TODO: Compare the sim and em outputs
    # return False
    keys = copy.deepcopy(list(obs2.keys()))
    for host in keys:
        if host in translation:
            obs2[translation[host]] = obs2.pop(host)

    for host, host_info in obs1.items():
        assert host in obs2, f"key {host} not in obs2 {obs2.keys()}"
        host_info2 = obs2.pop(host)
        if host == 'success':
            assert host_info == host_info2
        else:
            for key, value in host_info.items():
                assert key in host_info2, f"key {key} not in obs2"
                value2 = host_info2.pop(key)
                if key == 'System info':
                    np.testing.assert_equal(value,value2, f"{value} != {value2}")
                if key == 'Interface':
                    assert len(value) == len(value2), f"{value} != {value2}"
                    for interface in value:
                        interface2 = None
                        if 'Interface Name' in interface:
                            if interface2 is None:
                                for i2 in value2:
                                    if 'Interface Name' in i2 and i2['Interface Name'] == interface['Interface Name']:
                                        interface2 = i2
                                        break
                            assert interface2 is not None, f"Interface {interface['Interface Name']} not found in other observation"
                        subnet = None
                        subnet2 = None
                        if 'Subnet' in interface:
                            if interface2 is None:
                                for i2 in value2:
                                    if 'Subnet' in i2 and i2['Subnet'].netmask == interface['Subnet'].netmask:
                                        interface2 = i2
                                        break
                                assert interface2 is not None
                            else:
                                assert interface2['Subnet'].netmask == interface['Subnet'].netmask, f"The subnets netmasks differ {interface['Subnet'].netmask} != {interface2['Subnet'].netmask}"
                            subnet = interface['Subnet']
                            subnet2 = interface2['Subnet']
                        if 'IP Address' in interface:
                            if interface2 is None:
                                for i2 in value2:
                                    if 'IP Address' in i2:
                                        interface2 = i2
                                        break
                                assert interface2 is not None
                            else:
                                assert 'IP Address' in interface2
                            if subnet is not None:
                                assert interface['IP Address'] in subnet.hosts(), f"IP Address {interface['IP Address']} not in subnet {subnet}"
                                assert interface2['IP Address'] in subnet2.hosts(), f"IP Address {interface2['IP Address']} not in subnet {subnet2}"
                if key == 'Processes':
                    assert len(value) == len(value2), f"{value} != {value2}"
            assert host_info2 == {}, f'Not all values in host_info2 are in host_info1 \nRemaining data: {host_info2}'

    assert obs2 == {}, f'Not all values in obs2 are in obs1 \nRemaining data: {obs2}'
    return True


#TODO create custom generators and use in tests
class CustomGenerator:
    """Abstract class for generating specific 'random' behaviours"""
    @staticmethod
    def choice(a, size=None, replace=True, p=None, axis=0, shuffle=True):
        raise NotImplementedError

    @staticmethod
    def integers(low, high=None, size=None, dtype=np.int64, endpoint=False):
        raise NotImplementedError

    @classmethod
    def randint(cls, low, high=None, size=None, dtype=np.int64, endpoint=False):
        return cls.integers(low, high, size, dtype, endpoint)

    @staticmethod
    def random(size=None, dtype=np.float64, out=None):
        raise NotImplementedError

    @staticmethod
    def uniform(low=0.0, high=1.0, size=None):
        raise NotImplementedError


class AlwaysTrueGenerator(CustomGenerator):
    """Class that always returns an always True 'random' value"""
    @staticmethod
    def choice(a, size=None, replace=True, p=None, axis=0, shuffle=True):
        if size is None:
            return a[0]
        if replace:
            return [a[0] for _ in range(size)]
        else:
            return a[:size]

    @staticmethod
    def integers(low, high=None, size=None, dtype=np.int64, endpoint=False):
        if high is None:
            high = low
        if size is None:
            return high
        else:
            return [high for _ in range(size)]

    @staticmethod
    def random(size=None, dtype=np.float64, out=None):
        if size is None:
            return dtype(1.)
        else:
            return [dtype(1.) for _ in range(size)]

    @staticmethod
    def uniform(low=0.0, high=1.0, size=None):
        if size is None:
            return high
        else:
            return np.array([high for _ in range(size)])

    @staticmethod
    def shuffle(a):
        return a


class AlwaysFalseGenerator(CustomGenerator):
    """Class that always returns an always False 'random' value"""
    @staticmethod
    def choice(a, size=None, replace=True, p=None, axis=0, shuffle=True):
        raise NotImplementedError

    @staticmethod
    def integers(low, high=None, size=None, dtype=np.int64, endpoint=False):
        if high is None:
            low = 0
        if size is None:
            return low
        else:
            return [low for _ in range(size)]

    @staticmethod
    def random(size=None, dtype=np.float64, out=None):
        if size is None:
            return dtype(0.)
        else:
            return [dtype(0.) for _ in range(size)]

    @staticmethod
    def uniform(low=0.0, high=1.0, size=None):
        if size is None:
            return low
        else:
            return low

    @staticmethod
    def shuffle(a):
        return a.reverse()