#! /usr/bin/env python
# -*- coding: utf-8 -*-

from collections import defaultdict


class ACL:
    """ACL class.
    This class contains all information about an ACL.
    ACL belong to a firewall and are bounded to an edge in the multidigraph

    Parameters
    ----------
    name : String. The name of the ACL
    rules : Rule list. Contains all rules of the ACL
    """

    def __init__(self, name):
        self.name = name
        self.rules = []
        self.firewall = None

    def get_objects(self):
        """Get dict objects list of the acl (rules corresponding)

        Return
        ------
        Return a dictionary of key variable and rules corresponding
        """
        dict1 = {}

        for rule in self.rules:
            dict2 = rule.get_objects()
            keys = set(dict1).union(dict2)
            dict1 = dict((k, dict1.get(k, []) + dict2.get(k, [])) for k in keys)

        return dict1

    def get_services(self, min, max, protocol):
        """Get list of services in the interval (min, max) with the matching rules.

        Parameters
        ----------
        min : int. Minimal value
        max : int. Maximal value

        Return
        ------
        Return a dictionary of services as key with the list of rules enabling this services as value
        """
        dict1 = defaultdict(list)

        for rule in self.rules:
            if protocol is None and reduce(lambda x, y: x | y,
                                           [proto.v1.get_value() == 6 or proto.v1.get_value() == 17 for proto in
                                            rule.protocol], False):
                continue
            if protocol == 'tcp' and not reduce(lambda x, y: x | y,
                                                [proto.v1.get_value() == 6 for proto in rule.protocol], False):
                continue
            if protocol == 'udp' and not reduce(lambda x, y: x | y,
                                                [proto.v1.get_value() == 17 for proto in rule.protocol], False):
                continue
            for port in rule.port_dest:
                for i in port.get_services():
                    if min < i < max:
                        dict1[i].append(rule)

        return dict1