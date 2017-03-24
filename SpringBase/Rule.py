#! /usr/bin/env python
# -*- coding: utf-8 -*-

from ROBDD.robdd import Robdd
from ROBDD.synthesis import synthesize
from ROBDD.operators import Bdd
import re
from collections import defaultdict


class Rule:
    """Rule class.
    The rule class represent a firewall rule.
    Rule instance are created by the parser.

    Parameters
    ----------
    identifier : int. The identifier of the rule
    name : string. The name of the rule
    protocol : Operator. Protocols of the rule
    ip_source : Operator. Ips source of the rule
    port_source : Operator. Ports source of the rule
    ip_dest : Operator. Ips destination of the rule
    port_dest : Operator. Ports destination of the rule
    action : Action. The action of the rule (accept/deny/forward)
    rule_robdd : ROBDD. The ROBDD of the rule
    """
    def __init__(self, identifier, name, protocol, ip_source, port_source, ip_dest, port_dest, action):
        """Initialize the rule

        Parameters
        ----------
        see above
        """
        self.identifier = identifier
        self.name = name
        self.protocol = protocol
        self.protocol_name = []
        self.ip_source = ip_source
        self.ip_source_name = [[], []]
        self.port_source = port_source
        self.port_source_name = []
        self.ip_dest = ip_dest
        self.ip_dest_name = [[], []]
        self.port_dest = port_dest
        self.port_dest_name = []
        self.action = action
        self.rule_robdd = None

    def __getstate__(self):
        """Pickle (save) : delete rule_robdd"""
        state = self.__dict__.copy()
        del state['rule_robdd']
        return state

    def __setstate__(self, state):
        """Pickle (load) : reconstruct robdd"""
        self.__dict__.update(state)
        self.rule_robdd = None

    def search(self, pattern):
        """Perform search on rule.
        Check if pattern match attribute [protocol|ip|port]_name and search on operator list

        Parameters
        ----------
        pattern : the pattern to test

        Return
        ------
        Return the list of object matching
        """
        match = []

        check_not_none = lambda r: [r] if r else []
        test_match = lambda s, p: check_not_none(re.search(p, s if s else ''))

        match += test_match(str(self.identifier), pattern)
        match += test_match(self.name, pattern)
        match += [s for e in self.protocol for s in e.search(pattern) if s]
        [match.append(e) for s in self.protocol_name for e in test_match(s, pattern)]
        match += [s for e in self.ip_source for s in e.search(pattern) if s]
        [match.append(e) for s in self.ip_source_name for e in test_match(s, pattern)]
        match += [s for e in self.port_source for s in e.search(pattern) if s]
        [match.append(e) for s in self.port_source_name for e in test_match(s, pattern)]
        match += [s for e in self.ip_dest for s in e.search(pattern) if s]
        [match.append(e) for s in self.ip_dest_name for e in test_match(s, pattern)]
        match += [s for e in self.port_dest for s in e.search(pattern) if s]
        [match.append(e) for s in self.port_dest_name for e in test_match(s, pattern)]
        match += check_not_none(self.action.search(pattern))

        return match

    def toBDD(self):
        """Compute rhe ROBDD of the rule if rule_robdd is None else return rule_robdd

        Return
        ------
        Return the ROBDD
        """
        if self.rule_robdd is None:
            rule_robdd = Robdd.true()
            protocol_bdd = Robdd.false()
            ip_src_bdd = Robdd.false()
            port_src_bdd = Robdd.false()
            ip_dst_bdd = Robdd.false()
            port_dst_bdd = Robdd.false()

            for i in self.protocol:
                protocol_bdd = synthesize(protocol_bdd, Bdd.OR, i.toBDD(0))
            if self.protocol:
                rule_robdd = synthesize(rule_robdd, Bdd.AND, protocol_bdd)

            for i in self.ip_source:
                ip_src_bdd = synthesize(ip_src_bdd, Bdd.OR, i.toBDD(8))
            if self.ip_source:
                rule_robdd = synthesize(rule_robdd, Bdd.AND, ip_src_bdd)

            for i in self.port_source:
                port_src_bdd = synthesize(port_src_bdd, Bdd.OR, i.toBDD(40))
            if self.port_source:
                rule_robdd = synthesize(rule_robdd, Bdd.AND, port_src_bdd)

            for i in self.ip_dest:
                ip_dst_bdd = synthesize(ip_dst_bdd, Bdd.OR, i.toBDD(56))
            if self.ip_dest:
                rule_robdd = synthesize(rule_robdd, Bdd.AND, ip_dst_bdd)

            for i in self.port_dest:
                port_dst_bdd = synthesize(port_dst_bdd, Bdd.OR, i.toBDD(88))
            if self.port_dest:
                rule_robdd = synthesize(rule_robdd, Bdd.AND, port_dst_bdd)

            self.rule_robdd = rule_robdd

        return self.rule_robdd

    def get_objects(self):
        """Get dict objects list of the rule

        Return
        ------
        Return a dictionary of key variable and rules corresponding
        """
        dict1 = defaultdict(list)

        for i in self.protocol_name:
            dict1[i].append(self)
        for i in self.ip_source_name:
            dict1[i].append(self)
        for i in self.port_source_name:
            dict1[i].append(self)
        for i in self.ip_dest_name:
            dict1[i].append(self)
        for i in self.port_dest_name:
            dict1[i].append(self)

        return dict1

    def to_string(self, separator='\n'):
        """String representation of the rule

        Parameters
        ----------
        separator : string (optional, default='\n'). Used to define element separator of the rule

        Return
        ------
        res : string.
        """
        res = "  id: "
        res += str(self.identifier)
        if self.name:
            res += separator + "  name: "
            res += self.name
        res += separator + "  protocol: ["
        for i in self.protocol:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  ip_source: ["
        for i in self.ip_source:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  port_source: ["
        for i in self.port_source:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  ip_dest: ["
        for i in self.ip_dest:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  port_dest: ["
        for i in self.port_dest:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  action: "
        res += self.action.to_string()
        return res

    def to_string_list(self):
        res = list()
        res.append(str(self.identifier))
        tmp = ""
        if self.name:
            tmp = self.name
        res.append(tmp)
        tmp = ""
        for name in self.protocol_name:
            if len(name):
                tmp += name + ", "
        res.append(tmp)
        tmp = ""
        for i in self.protocol:
            tmp += i.to_string()
            tmp += ", "
        res.append(tmp)
        tmp = ""
        for name in self.ip_source_name:
            if len(name):
                tmp += name[0] + ", "
        res.append(tmp)
        tmp = ""
        for i in self.ip_source:
            tmp += i.to_string()
            tmp += ", "
        res.append(tmp)
        tmp = ""
        for name in self.port_source_name:
            if len(name):
                tmp += name + ", "
        res.append(tmp)
        tmp = ""
        for i in self.port_source:
            tmp += i.to_string()
            tmp += ", "
        res.append(tmp)
        tmp = ""
        for name in self.ip_dest_name:
            if len(name):
                tmp += name[0] + ", "
        res.append(tmp)
        tmp = ""
        for i in self.ip_dest:
            tmp += i.to_string()
            tmp += ", "
        res.append(tmp)
        tmp = ""
        for name in self.port_dest_name:
            if len(name):
                tmp += name + ", "
        res.append(tmp)
        tmp = ""
        for i in self.port_dest:
            tmp += i.to_string()
            tmp += ", "
        res.append(tmp)
        res.append(self.action.to_string())
        return res

    def new_to_string(self, fw, separator='\n'):
        res = "  id: "
        res += str(self.identifier)
        if self.name:
            res += separator + "  name: "
            res += self.name
        res += ' from ' + fw.fw.hostname

        res += separator + "  Zone source : " + str(self.ip_source_name[1])

        res += separator + "  Zone destination : " + str(self.ip_dest_name[1])

        res += separator + "  protocol: " + str(self.protocol_name)

        res += "" + separator + "  ip_source: " + str(self.ip_source_name[0])

        res += "" + separator + "  port_source: " + str(self.port_source_name)

        res += "" + separator + "  ip_dest: " + str(self.ip_dest_name[0])

        res += "" + separator + "  port_dest: " + str(self.port_dest_name)

        res += "" + separator + "  action: "
        res += self.action.to_string()

        res += '\n\n'

        return res