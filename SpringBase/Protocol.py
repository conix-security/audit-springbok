#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from ROBDD.robdd import Robdd
from ROBDD.synthesis import synthesize
from ROBDD.operators import Bdd
import math
import socket


class Protocol:
    """Protocol class.
    This class describe a protocol element

    Parameters
    ----------
    protocol : int or string. The protocol name or value
    """
    def __init__(self, protocol):
        try:
            self.protocol = int(protocol)
        except ValueError:
            self.protocol = socket.getprotobyname(protocol)

    def search(self, pattern):
        """Search if pattern match string or number value.

        Parameters
        ----------
        pattern : string. the pattern to match

        Return
        ------
        Return the object matching if any else return None
        """
        num = re.search(pattern, str(self.protocol))
        string = None
        if Protocol.get_service_name(self.protocol):
            string = re.search(pattern, Protocol.get_service_name(self.protocol))
        return num if num else string

    def toBDD(self, index, limit=0):
        """Construct the ROBDD.

        Parameters
        ----------
        index : int. Used for ROBDD variable index
        limit : int (optional, default=0). The limit bit used for range representation

        Return
        ------
        Return the computed ROBDD.
        """
        # Protocol : 8 bits
        res = Robdd.true()
        protocol_size = 8
        for i in range(protocol_size - limit):
            if (self.protocol >> (protocol_size - i - 1)) & 1:
                res = synthesize(res, Bdd.AND, Robdd.make_x(index + i))
            else:
                res = synthesize(res, Bdd.AND, Robdd.make_not_x(index + i))

        return res

    @staticmethod
    def range2bdd(min_value, max_value, index, interval=(0, 2**8 - 1)):
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
            return Protocol(interval[0]).toBDD(index, int(math.log(interval[1] + 1 - interval[0], 2)))

        def new_min_interval(inter):
            min_v = inter[0]
            max_v = inter[0] + 2**(int(math.log(inter[1] + 1 - inter[0], 2)) - 1) - 1
            return (min_v, max_v)

        def new_max_interval(inter):
            min_v = inter[0] + 2**(int(math.log(inter[1] + 1 - inter[0], 2)) - 1)
            max_v = inter[1]
            return (min_v, max_v)

        return synthesize(Protocol.range2bdd(min_value, max_value, index, new_min_interval(interval)),
                          Bdd.OR,
                          Protocol.range2bdd(min_value, max_value, index, new_max_interval(interval)))

    def get_value(self):
        """Return the protocol value"""
        return int(self.protocol)

    def to_string(self):
        """Return the protocol string value"""
        str_proto = Protocol.get_service_name(self.protocol)
        return "%s (%d)" % (str_proto, self.protocol) if str_proto else str(self.protocol)

    @staticmethod
    def get_service_name(proto):
        """Try to retrieve the protocol name from the protocol number

        Parameters
        ----------
        proto : int. the protocol number

        Return
        ------
        Return the string protocol name if found else None
        """
        for p in [a[8:] for a in dir(socket) if a.startswith('IPPROTO_')]:
            try:
                if socket.getprotobyname(p) == proto:
                    return p.lower()
            except:
                pass
        return None