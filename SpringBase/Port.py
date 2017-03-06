#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from ROBDD.robdd import Robdd
from ROBDD.synthesis import synthesize
from ROBDD.operators import Bdd
import socket
import math


class Port:
    """Port class.
    This class describe a port element.

    Parameters
    ----------
    port : int or string. The port name or number
    """
    def __init__(self, port):
        """Initialize a port class.

        Parameters
        ----------
        see above.
        """
        try:
            self.port = int(port)
        except ValueError:
            print port
            self.port = socket.getservbyname(port)

    def search(self, pattern):
        """Search if pattern match string or number value.

        Parameters
        ----------
        pattern : string. the pattern to match

        Return
        ------
        Return the object matching if any else return None
        """
        num = re.search(pattern, str(self.port))
        string = None
        if Port.get_service_name(self.port):
            string = re.search(pattern, Port.get_service_name(self.port))
        return num if num else string

    def toBDD(self, index, limit=0):
        """Compute the ROBDD.

        Parameters
        ----------
        index : int. Used for ROBDD variable index
        limit : int (optional, default=0). The limit bit used for range representation.

        Return
        ------
        Return the comuted ROBDD
        """
        # Port: 16 bits
        res = Robdd.true()
        port_size = 16
        for i in range(port_size - limit):
            if (self.port >> (port_size - i - 1)) & 1:
                res = synthesize(res, Bdd.AND, Robdd.make_x(index + i))
            else:
                res = synthesize(res, Bdd.AND, Robdd.make_not_x(index + i))

        return res

    @staticmethod
    def range2bdd(min_value, max_value, index, interval=(0, 2**16 - 1)):
        """Static method for construction ROBDD range

        Parameters
        ----------
        min_value : int. the start of the range
        max_value : the end of the range
        index : the index for ROBDD construction variable name
        interval : (int, int). the interval to check (used for recursivity)

        Return
        ------
        Return the corresponding ROBDD
        """
        if interval[0] > max_value or interval[1] < min_value:
            return Robdd.false()

        if interval[0] >= min_value and interval[1] <= max_value:
            return Port(interval[0]).toBDD(index, int(math.log(interval[1] + 1 - interval[0], 2)))

        def new_min_interval(inter):
            min_v = inter[0]
            max_v = inter[0] + 2**(int(math.log(inter[1] + 1 - inter[0], 2)) - 1) - 1
            return (min_v, max_v)

        def new_max_interval(inter):
            min_v = inter[0] + 2**(int(math.log(inter[1] + 1 - inter[0], 2)) - 1)
            max_v = inter[1]
            return (min_v, max_v)

        return synthesize(Port.range2bdd(min_value, max_value, index, new_min_interval(interval)),
                          Bdd.OR,
                          Port.range2bdd(min_value, max_value, index, new_max_interval(interval)))

    def get_value(self):
        """Return the port value"""
        return int(self.port)

    def to_string(self):
        """Return the port value in string"""
        str_port = Port.get_service_name(self.port)
        return "%s (%d)" % (str_port, self.port) if str_port else str(self.port)

    @staticmethod
    def get_service_name(port):
        """Try to retrieve the port name from the protocol number

        Parameters
        ----------
        port : int. the port number

        Return
        ------
        Return the string port name if found else None
        """
        try:
            return socket.getservbyport(port)
        except:
            return None

    def seria_compare(self):
        serialize = str(self.port)
        return serialize