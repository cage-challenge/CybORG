import copy

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
                    assert value == value2, f"{value} != {value2}"
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
