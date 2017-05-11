#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re


class Interface:
    """Interface class.
    This class contains all informations about an interface of a firewall.
    Interface contains network node who are used for the topology.

    Parameters
    ----------
    nameif : string. The name interface of the Interface (ex: GigabitEthernet0/1)
    network : Ip. An Ip object designing the network
    name : string. The name of the interface (ex: inside)
    sub_interfaces : Interface list. A list of sub-interface of this interface
    """

    def __init__(self, nameif, network=None, name=None, sub_interfaces=[]):
        """Initialize the Interface with empty values"""
        self.nameif = nameif
        self.network = network
        self.name = name
        self.sub_interfaces = sub_interfaces
        self.attributes = dict()


    def get_subif_by_nameif(self, nameif):
        """Find a sub-interface by his name interface.

        Parameters
        ----------
        nameif : the name interface to find.

        Return
        ------
        Return the Interface if found else return None.
        """
        for i in self.sub_interfaces:
            if i.nameif == nameif:
                return i
        return None

    def get_subif_by_name(self, name):
        """Found the sub-interface by his name.

        Parameters
        ----------
        name : string. The name of the interface to find

        Return
        ------
        Return the Interface if found else return None
        """
        for i in self.sub_interfaces:
            if i.name == name:
                return i
        return None

    def to_string(self):
        """Return the interfaces

        Return
        ------
        res : string
        """
        res = ""
        if self.nameif is not None:
            res += self.nameif
        if self.name:
            res += " - "
            res += self.name
        res += ": "
        if self.network:
            res += self.network.to_string()
        else:
            res += "None"
        res += "\n"
        for i in self.sub_interfaces:
            res += i.to_string()
        return res

    def short_name(self):
        """Compute a short name for the interface name.
        (ex: GigabitEhternet0/1.2 -> G0/1.2)

        Return
        ------
        Return the computed short name
        """
        res = ""
        split = re.split('[a-zA-Z]+', self.nameif)
        if len(split) >= 2:
            res = self.nameif[0] + split[1]
        return self.nameif