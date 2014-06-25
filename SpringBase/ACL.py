#! /usr/bin/env python
# -*- coding: utf-8 -*-

from collections import defaultdict
import copy


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

    def get_rules(self):
        """Get the ACL rules and the rules of chained ACLs.

        Return
        ------
        Return a list of rules.
        """
        return self._get_rules(set())

    def _get_rules(self, mark):
        """Recursive call for ACL graph traversal

        Return
        ------
        Return the rules of each traversed ACL.
        """
        if self in mark:
            return []

        mark.add(self)
        rule_list = list(self.rules)
        chain_list = [rule.action.chain for rule in self.rules if rule.action.is_chained()]

        for chain in chain_list:
            rule_list += chain._get_rules(mark)

        return rule_list

    def get_rules_path(self):
        """Get all possible list of rules from traversing the ACLs graph

        Return
        ------
        Return a list of list of rules for each possible path.
        """
        return self._get_rules_path([], [], [])

    def _get_rules_path(self, result, stack, visited):
        """Recursive call for ACL graph traversal

        Return
        ------
        Return a list of list of rules for each possible path."""
        if self not in visited:
            stack.append([r for r in self.rules])
            visited.append(self)
        list_of_result = []

        while stack:
            rules_list = stack[-1]
            while rules_list:
                rule = rules_list.pop(0)
                result.append([rule, False])
                if rule.action.is_chained():
                    new_list = [[r, a] for r, a in result]
                    new_list[-1][1] = True
                    new_stack = [list(rules) for rules in stack]
                    list_of_result += rule.action.chain._get_rules_path(new_list, new_stack, list(visited))
                if rule.action.is_return():
                    # return : remove all rule to access pushed rule from previous acl in stack
                    new_list = [[r, a] for r, a in result]
                    new_list[-1][1] = True
                    new_stack = [list(rules) for rules in stack]
                    new_stack.pop()
                    # special case (Return in first list)
                    new_visited = list(visited)
                    new_visited.pop()
                    if not new_visited:
                        new_stack.append([self.rules[-1]])
                        new_visited.append(self)
                    list_of_result += new_visited[-1]._get_rules_path(new_list, new_stack, new_visited)
            stack.pop()
            visited.pop()

        return [result] + list_of_result

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