#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re


class ErrorType(object):
    """ErrorType class.
    A class enumeration of all error type."""
    INT_MASK_SHADOW = 0
    INT_MASK_REDUNDANT = 1
    INT_MASK_REDUNDANT_CORRELATION = 2
    INT_PART_CORRELATION = 3
    INT_PART_GENERALIZATION = 4
    INT_PART_REDUNDANT = 5
    DIST_SHADOW = 6
    DIST_RAISED = 7
    DIST_REDUNDANT = 8
    DIST_CORRELATE = 9
    ERROR = 10
    WARNING = 11


class ErrorMessage(object):
    """ErrorMessage class.
    a class containing all error message"""
    INT_MASK_SHADOW = """This rule intended to accept/deny
some packets which have been
denied/accepted by preceding rules.
This contradiction reveals a
misconfiguration."""
    INT_MASK_REDUNDANT = """All the packets have been
accepted/denied by preceding rules
or will not take this path."""
    INT_MASK_REDUNDANT_CORRELATION = """Part of the packets for
this rule have been denied/accepted.
Others are either accepted/denied or
will not take this path.
This rule itself is redundant since
it will not match any packets. Some
preceding rule has correlation with
this rule also."""
    INT_PART_CORRELATION = """Part of the packets intend to be
accepted/denied by this rule have been
denied/accepted by preceding rules."""
    INT_PART_GENERALIZATION = """This rule is a generalization
of preceding rules since preceding
rules match a subset of the current
rule but defined a different action."""
    INT_PART_REDUNDANT = """If preceding rules are removed,
all the packets that match preceding
rules can still be accepted/denied
to the current rule. Therefore,
preceding rules are redundant."""
    DIST_SHADOW = """This rule is shadowed by upstream
ACLs. It tries to accept some
packets that are blocked on
all reachable path."""
    DIST_RAISED = """This probably reveals a raised
security level. Certain packets
might be allowed to access part
of the network path but not to
the end of this path"""
    DIST_REDUNDANT = """This is probably a redundancy
since the packets to be denied
will not reach this ACL anyway.
However, multiple lines of
defense are often encouraged
in practice to increase overall
security level."""
    DIST_CORRELATE = """This reveal an overlapping rule.
Part of the packets intend to
be accepted/denied by this rule
have been denied/accepted by
upstream ACLs."""


class AnomalyError:
    """AnomalyError class.
    A class for generating anomaly error message
    """
    def __init__(self, error, status, rule, parent_rules):
        self.error = error
        self.status = status
        self.rule = rule
        self.parent_rules = parent_rules

    @staticmethod
    def error_message(error, status, rule, parent_rules):
        """Static method for generating anomaly error message.

        Parameters
        ----------
        error : ErrorType. The error type id.
        status : ErrorType. The error class (ERROR or WARNING)
        rule : Rule. The blamed rule
        parent_rule : list of Rule. The rule associate with the blamed rule
        """
        result = ""

        result += "WARNING " if status == ErrorType.ERROR else "NOTIFICATION "
        result += "("
        if error == ErrorType.INT_MASK_SHADOW:
            result += "masked : shadowed"
        elif error == ErrorType.INT_MASK_REDUNDANT:
            result += "masked : redundant"
        elif error == ErrorType.INT_MASK_REDUNDANT_CORRELATION:
            result += "masked : redundant and overlap"
        elif error == ErrorType.INT_PART_CORRELATION:
            result += "partially masked : overlap"
        elif error == ErrorType.INT_PART_GENERALIZATION:
            result += "partially masked : generalized"
        elif error == ErrorType.INT_PART_REDUNDANT:
            result += "partially masked : redundant"
        elif error == ErrorType.DIST_SHADOW:
            result += "shadowed"
        elif error == ErrorType.DIST_RAISED:
            result += "raised security level"
        elif error == ErrorType.DIST_REDUNDANT:
            result += "redundant"
        elif error == ErrorType.DIST_CORRELATE:
            result += "overlap"
        result += ") :\n"

        result += "Rule : "
        result += rule.to_string(' ')

        if parent_rules:
            result += "\nWith rule :"
            for r in parent_rules:
                result += '\n  %s' % r.to_string(' ')

        return result


def get_error_help(error_message, detection_type):
    """Get error message details using regex on an error message and the detection type.

    Parameters
    ----------
    error_message : string. The error message
    detection_type : string ('internal', 'distributed'). The detection type
    """
    message = "No information"
    if detection_type == 'internal':
        if re.search('\(masked : shadowed\)', error_message):
            message = ErrorMessage.INT_MASK_SHADOW
        elif re.search('\(masked : redundant\)', error_message):
            message = ErrorMessage.INT_MASK_REDUNDANT
        elif re.search('\(masked : overlap and redundant\)', error_message):
            message = ErrorMessage.INT_MASK_REDUNDANT_CORRELATION
        elif re.search(r'\(partially masked : overlap\)', error_message):
            message = ErrorMessage.INT_PART_CORRELATION
        elif re.search(r'\(partially masked : generalized\)', error_message):
            message = ErrorMessage.INT_PART_GENERALIZATION
        elif re.search(r'\(partially masked : redundant\)', error_message):
            message = ErrorMessage.INT_PART_REDUNDANT
    elif detection_type == 'distributed':
        if re.search('shadowed', error_message):
            message = ErrorMessage.DIST_SHADOW
        elif re.search('raised', error_message):
            message = ErrorMessage.DIST_RAISED
        elif re.search('redundant', error_message):
            message = ErrorMessage.DIST_REDUNDANT
        elif re.search('overlap', error_message):
            message = ErrorMessage.DIST_CORRELATE

    return message