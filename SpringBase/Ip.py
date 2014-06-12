#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from ROBDD.robdd import Robdd
from ROBDD.synthesis import synthesize
from ROBDD.operators import Bdd
import math


class Ip:
    """Ip class.
    This class contains information about a network or a host.

    Parameters
    ----------
    ip : int or string. The ip of the network
    mask : int or string (optional, default='255.255.255.255'). The mask for the network
    detect_class : bool. If True, assign a mask corresponding of the ip class
    (ex : 192.168.42.42 -> class C -> '255.255.255.0')
    """
    def __init__(self, ip, mask='255.255.255.255', detect_class=False):
        """Initialize a Ip class.

        Parameters
        ----------
        see above.
        """
        if isinstance(ip, str):
            self.ip = Ip.toInteger(ip)
        else:
            self.ip = ip

        if not detect_class:
            if isinstance(mask, str):
                self.mask = Ip.toInteger(mask)
            else:
                self.mask = mask
        else:
            self.mask = Ip.toInteger(Ip.detectClass(ip))

    def search(self, pattern):
        """Search if pattern match ip or mask value

        Parameters
        ----------
        pattern : string. the pattern to match

        Return
        ------
        Return the object matching if any else return None
        """
        ip = re.search(pattern, Ip.toString(self.ip))
        mask = re.search(pattern, Ip.toString(self.mask))
        return ip if ip else mask

    def toBDD(self, index):
        """Compute the corresponding ROBDD of the Ip

        Parameters
        ----------
        index : int. The start point of the variable name

        Return
        ------
        Return the corresponding ROBDD
        """
        # Ip: 32 bits
        res = Robdd.true()
        ip_size = 32
        for i in range(ip_size - (32 - Ip.MaskToCidr(self.mask))):
            if (self.ip >> (ip_size - i - 1)) & 1:
                res = synthesize(res, Bdd.AND, Robdd.make_x(index + i))
            else:
                res = synthesize(res, Bdd.AND, Robdd.make_not_x(index + i))

        return res

    @staticmethod
    def range2bdd(min_value, max_value, index, interval=(0, 2**32 - 1)):
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
            return Ip(interval[0], 2**(int(math.log(interval[1] + 1 - interval[0], 2)))).toBDD(index)

        def new_min_interval(inter):
            min_v = inter[0]
            max_v = inter[0] + 2**(int(math.log(inter[1] + 1 - inter[0], 2)) - 1) - 1
            return (min_v, max_v)

        def new_max_interval(inter):
            min_v = inter[0] + 2**(int(math.log(inter[1] + 1 - inter[0], 2)) - 1)
            max_v = inter[1]
            return (min_v, max_v)

        return synthesize(Ip.range2bdd(min_value, max_value, index, new_min_interval(interval)),
                          Bdd.OR,
                          Ip.range2bdd(min_value, max_value, index, new_max_interval(interval)))

    def get_value(self):
        """Return the ip value"""
        return int(self.ip)

    def to_string(self):
        """Return the Ip instance to string

        Return
        ------
        res : string.
        """
        res = ""
        res += Ip.toString(self.ip)
        if not self.mask == 0xFFFFFFFF:
            res += " / "
            res += str(Ip.MaskToCidr(self.mask))
        return res

    @staticmethod
    def toString(i):
        """Static method for converting an Ip number to string.

        Parameters
        ----------
        i : int. The ip number

        Return
        ------
        Return the string representing the ip number
        """
        res = ""
        res += str((i >> 24 & 0xFF))
        res += "."
        res += str((i >> 16 & 0xFF))
        res += "."
        res += str((i >> 8 & 0xFF))
        res += "."
        res += str((i & 0xFF))
        return res

    @staticmethod
    def toInteger(s):
        """Static method to convert a ip string to his equivalent number

        Parameters
        ----------
        s : string. The ip string

        Return
        ------
        Return the integer representing the ip string
        """
        res = 0
        if isinstance(s, str):
            list = s.split('.')
            for i in list:
                res <<= 8
                res += int(i)
        return res

    @staticmethod
    def detectClass(addr):
        """Static method for detecting class (class A, B, C)

        Parameters
        ----------
        addr : int or string. The ip address

        Return
        ------
        Return a string representing the mask class
        """
        tmp = addr
        if isinstance(addr, str):
            tmp = Ip.toInteger(addr)

        if (tmp >> 31) == 0:
            return '255.0.0.0'
        elif (tmp >> 30) == 2:
            return '255.255.0.0'
        else:
            return '255.255.255.0'

    @staticmethod
    def CidrToMask(i):
        """Static method converting a CIDR number to the corresponding mask number

        Parameters
        ----------
        i : int. The CIDR value

        Return
        ------
        Return the corresponding mask number
        """
        res = 0
        count = 0
        while count < i:
            res <<= 1
            res |= 1
            count += 1

        res <<= (32 - i)

        return res

    @staticmethod
    def MaskToCidr(mask):
        """Static method converting a mask to his CIDR value

        Parameters
        ----------
        mask : int. the mask number value

        Return
        ------
        Return the corresponding CIDR number
        """
        i = 32

        while mask & 1 == 0 and i > 0:
            i -= 1
            mask >>= 1

        return i

    @staticmethod
    def ListContains(subnet_list, ip):
        """Check if an ip is a subset, a superset or equal to an element in the subnet_list

        Parameters
        ----------
        subnet_list : the list of ip network
        ip : the network to check

        Return
        ------
        Return the network who match if any else return None.
        """
        for i in subnet_list:
            # Check if i C ip or ip C i or ip == i
            if i.ip & i.mask & ip.mask == ip.ip & i.mask & ip.mask:
                return i
        return None
