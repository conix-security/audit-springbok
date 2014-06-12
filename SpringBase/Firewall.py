#! /usr/bin/env python
# -*- coding: utf-8 -*-

import Gtk.Gtk_Main
from Protocol import Protocol
from Ip import Ip
from Port import Port


class Firewall:
    """Firewall class.
    This class contains all information about the Firewall.
    Firewall are constructed by the parser who initialize all his values.

    Parameters
    ----------
    interfaces : Interface list. Contain all interface object
    type : string. Indetify the firewall type (CiscoAsa, JuniperNetscreeen, ...)
    hostname : string. Name of the firewall
    ready : bool. Firewall state used for ROBDD background construction. True when the ROBDD construction finish.
    unused_objects : string set. Set of declared object who are not used in ACL.
    unbounded_rules : string set. Set of declared rules that are not bounded (used for CiscoAsa)
    """
    def __init__(self):
        """Initialize the firewall with empty values"""
        self.interfaces = []
        self.acl = []
        self.type = None
        self.name = None
        self.hostname = None
        self.ready = False
        self.unused_objects = set()
        self.unbounded_rules = set()
        self.dictionnary = {}

    def get_interface_by_name(self, name):
        """Find an interface by name

        Parameters
        ----------
        name : string. The name of the interface to find

        Return
        ------
        Return the corresponding interface if found else return None.
        """
        for i in self.interfaces:
            if i.name == name:
                return i
            for u in i.sub_interfaces:
                if u.name == name:
                    return u
        return None

    def get_interface_by_nameif(self, nameif):
        """Find an interface by name interface

        Parameters
        ----------
        name : string. The name interface of the interface to find

        Return
        Return the corresponding interface if found else return None.
        ------
        """
        for i in self.interfaces:
            if i.nameif == nameif:
                return i
            for u in i.sub_interfaces:
                if u.name == nameif:
                    return u
        return None

    def get_acl_by_name(self, name):
        for acl in self.acl:
            if acl.name == name:
                return acl
        return None

    def get_nb_rules(self):
        count = 0
        for acl in self.acl:
            count += len(acl.rules)
        return count

    def get_rule_by_id(self, id):
        """Find a rule by his identifier

        Parameters
        ----------
        id : int. The identifier of the rule to find

        Return
        ------
        Return the corresponding rule if found else return None.
        """
        for acl in self.acl:
            for rule in acl.rules:
                if rule.identifier == id:
                    return rule
        return None

    def del_rule_by_id(self, id):
        """Delete a rule by his identifier

        Parameters
        ----------
        id : int. The identifier of the rule to delete

        Return
        ------
        Return True if the rule his deleted else return False
        """
        for acl in self.acl:
            for rule in acl.rules:
                if rule.identifier == id:
                    acl.rules.remove(rule)
                    return True
        return False

    def build_bdd(self):
        """Function to build the ROBDD rules.
        This function build the ROBDD of each rules of each interfaces and sub-interfaces.
        This function also update gtk event for preventing freezing.
        At the end, this function set ready to True, enabling using ROBDD of this firewall
        """
        for a in self.acl:
            for rule in a.rules:
                rule.toBDD()
                Gtk.Gtk_Main.Gtk_Main().update_interface()
        self.ready = True

    def is_ready(self):
        """Verify if the firewall ROBDD construction is finished

        Return
        ------
        Return True if the firewall is ready, false otherwise
        """
        return self.ready

    def resolve(self, name):
        """Try to resolve a name in the firewall dictionary.
        Construct a dict of resolved reference catalogued ('object', 'protocol', 'ip', 'port')

        Parameters
        ----------
        name : string. The name to resolve

        Return
        ------
        Return a dictionary of list of resolved object
        """
        dict1 = {}

        if name not in self.dictionnary:
            return dict1

        for elem in self.dictionnary[name]:
            if isinstance(elem.items()[0][1], str):
                if not dict1.get('object'):
                    dict1['object'] = []
                dict1['object'].append(elem.items()[0][1])
                dict2 = self.resolve(elem.items()[0][1])
                keys = set(dict1).union(dict2)
                dict1 = dict((k, dict1.get(k, []) + dict2.get(k, [])) for k in keys)
            elif isinstance(elem.items()[0][1].v1, Protocol):
                if not dict1.get('protocol'):
                    dict1['protocol'] = []
                dict1['protocol'].append(elem.items()[0][1].to_string())
            elif isinstance(elem.items()[0][1].v1, Ip):
                if not dict1.get('ip'):
                    dict1['ip'] = []
                dict1['ip'].append(elem.items()[0][1].to_string())
            elif isinstance(elem.items()[0][1].v1, Port):
                if not dict1.get('port'):
                    dict1['port'] = []
                dict1['port'].append(elem.items()[0][1].to_string())

        return dict1

    def get_objects(self):
        """Get dict objects list of the firewall (the dictionary and rules corresponding)

        Return
        ------
        Return a dictionary of key variable and rules corresponding
        """
        dict1 = dict(self.dictionnary)

        for acl in self.acl:
            dict2 = acl.get_objects()
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
        dict1 = {}

        for acl in self.acl:
            dict2 = acl.get_services(min, max, protocol)
            keys = set(dict1).union(dict2)
            dict1 = dict((k, dict1.get(k, []) + dict2.get(k, [])) for k in keys)

        return dict1

    def to_string(self):
        """Return the firewall rules

        Return
        ------
        res : string.
        """
        res = ""

        res += "Interfaces :\n"
        for i in self.interfaces:
            res += "\t"
            res += i.to_string()
            res += "\n"

        res += "Rules :\n"
        for acl in self.acl:
            for rule in acl.rules:
                res += rule.to_string()
                res += "\n"

        return res
