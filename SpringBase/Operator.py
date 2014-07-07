#! /usr/bin/env python
# -*- coding: utf-8 -*-

from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from ROBDD.synthesis import negate_bdd


class Operator:
    """Operator class.
    This class contains contains operator describing rule element.
    Each element of a rule is an operator who design a set of Port, Protocol or Ip

    Parameters
    ----------
    operator : string. String can be LT, GT, EQ, NEQ, RANGE
    v1 : value 1. Can be a Protocol, Port or Ip
    v2 : value 2. Used for range operator. Can be Protocol, Port or Ip
    """
    def __init__(self, operator, v1, v2=None):
        """Initialize an Operator

        Parameters
        ----------
        see above
        """
        self.operator = operator
        self.v1 = v1
        self.v2 = v2

    def get_len(self):
        """Return the lenght of a operator subset"""
        if self.operator == 'LT':
            return int(self.v1.get_value())
        elif self.operator == 'GT':
            return 65535 - int(self.v1.get_value())
        elif self.operator == 'EQ':
            return 1
        elif self.operator == 'NEQ':
            return 65534
        elif self.operator == 'RANGE':
            return int(self.v2.get_value()) - int(self.v1.get_value())
        else:
            return 1

    def search(self, pattern):
        """Search if attribute value match the pattern

        Parameters
        ----------
        pattern : string. The pattern to match

        Return
        ------
        Return the list of value matching
        """
        match = [self.v1.search(pattern)]
        if self.operator == 'RANGE':
            match.append(self.v2.search(pattern))
        return match

    def toBDD(self, index):
        """Construct the ROBDD

        Parameters
        ----------
        index : int. Used for variable index in ROBDD.

        Return
        ------
        Return the computed ROBDD
        """
        if self.operator == 'LT':
            if isinstance(self.v1, Protocol):
                return Protocol.range2bdd(0, self.v1.get_value(), index)
            elif isinstance(self.v1, Ip):
                return Ip.range2bdd(0, self.v1.ip | ~self.v1.mask & 0xFFFFFFFF, index)
            elif isinstance(self.v1, Port):
                return Port.range2bdd(0, self.v1.get_value(), index)
            else:
                return self.v1.toBDD(index)
        elif self.operator == 'GT':
            if isinstance(self.v1, Protocol):
                return Protocol.range2bdd(self.v1.get_value(), 2**8 - 1, index)
            elif isinstance(self.v1, Ip):
                return Ip.range2bdd(self.v1.ip & self.v1.mask, 2**32 - 1, index)
            elif isinstance(self.v1, Port):
                return Port.range2bdd(self.v1.get_value(), 2**16 - 1, index)
            else:
                return self.v1.toBDD(index)
        elif self.operator == 'EQ':
            return self.v1.toBDD(index)
        elif self.operator == 'NEQ':
            return negate_bdd(self.v1.toBDD(index))
        elif self.operator == 'RANGE':
            if isinstance(self.v1, Protocol):
                return Protocol.range2bdd(self.v1.get_value(), self.v2.get_value(), index)
            elif isinstance(self.v1, Ip):
                return Ip.range2bdd(self.v1.ip & self.v1.mask, self.v2.ip | ~self.v2.mask & 0xFFFFFFFF, index)
            elif isinstance(self.v1, Port):
                return Port.range2bdd(self.v1.get_value(), self.v2.get_value(), index)
            else:
                return self.v1.toBDD(index)
        else:
            return self.v1.toBDD(index)

    def get_services(self):
        """Get the service list of this operator

        Return
        ------
        Return the list of service number of this operator
        """
        res = []

        if not (isinstance(self.v1, Port) or isinstance(self.v1, Protocol)):
            return res

        if self.operator == 'LT':
            if isinstance(self.v1, Port):
                [res.append(i) for i in xrange(0, self.v1.port + 1)]
            elif isinstance(self.v1, Protocol):
                [res.append(i) for i in xrange(0, self.v1.protocol + 1)]
        elif self.operator == 'GT':
            if isinstance(self.v1, Port):
                [res.append(i) for i in xrange(self.v1.port, 65535 + 1)]
            elif isinstance(self.v1, Protocol):
                [res.append(i) for i in xrange(self.v1.protocol, 255 + 1)]
        elif self.operator == 'EQ':
            if isinstance(self.v1, Port):
                res.append(self.v1.port)
            elif isinstance(self.v1, Protocol):
                res.append(self.v1.protocol)
        elif self.operator == 'NEQ':
            if isinstance(self.v1, Port):
                [res.append(i) for i in xrange(0, self.v1.port)]
                [res.append(i) for i in xrange(self.v1.port + 1, 65535 + 1)]
            elif isinstance(self.v1, Protocol):
                [res.append(i) for i in xrange(0, self.v1.protocol)]
                [res.append(i) for i in xrange(self.v1.protocol + 1, 255 + 1)]
        elif self.operator == 'RANGE':
            if isinstance(self.v1, Port):
                [res.append(i) for i in xrange(self.v1.port, self.v2.port + 1)]
            elif isinstance(self.v1, Protocol):
                [res.append(i) for i in xrange(self.v1.protocol, self.v2.protocol + 1)]

        return res

    def toggle(self):
        """Return the invert of the current Operator

        Return
        ------
        Return a list of operators matching the invert of the current operator
        """
        if self.operator == 'LT':
            return [Operator('GT', self.v1, self.v2)]
        elif self.operator == 'GT':
            return [Operator('LT', self.v1, self.v2)]
        elif self.operator == 'EQ':
            return [Operator('NEQ', self.v1, self.v2)]
        elif self.operator == 'NEQ':
            return [Operator('EQ', self.v1, self.v2)]
        elif self.operator == 'RANGE':
            return [Operator('LT', self.v1, None), Operator('GT', self.v2, None)]
        else:
            return [self]

    def to_string(self):
        """Return the operator in string format"""
        if self.operator == 'LT':
            return "< %s" % self.v1.to_string()
        elif self.operator == 'GT':
            return "> %s" % self.v1.to_string()
        elif self.operator == 'EQ':
            return "%s" % self.v1.to_string()
        elif self.operator == 'NEQ':
            return "!= %s" % self.v1.to_string()
        elif self.operator == 'RANGE':
            return "%s-%s" % (self.v1.to_string(), self.v2.to_string())
        else:
            return "%s %s %s" % (self.operator, self.v1.to_string(), self.v2.to_string())
