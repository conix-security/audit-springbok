#! /usr/bin/env python
# -*- coding: utf-8 -*-

from ACL import ACL
import re


class Action:
    """Action class.
    This class describe the action of a rule.
    A rule can be accept, deny or forward.

    Parameters
    ----------
    chain : ACL or bool or string. Specify the action for the rule
    parent_acl : Acl. The calling ACL
    parent_rule_id : int. The id of the calling rule
    goto : bool. (see iptables goto option to understand)
    """
    def __init__(self, chain, goto=False):
        self.chain = chain
        self.goto = goto

    def is_chained(self):
        """Return true if the action is chained to another ACL, False otherwise"""
        return isinstance(self.chain, ACL)

    def is_return(self):
        """Return true if the action is return, False otherwise"""
        return isinstance(self.chain, str) and re.match(self.chain, 'RETURN', re.I)

    def search(self, pattern):
        """Search if pattern match action or string representation of the action.

        Parameters
        ----------
        pattern : string. the pattern to match

        Return
        ------
        Return the object matching
        """
        result = None
        if isinstance(self.chain, ACL):
            result = re.search(pattern, self.chain.name) or result

        if isinstance(self.chain, bool):
            result = re.search(pattern, str(self.chain)) or result
            if self.chain:
                result = re.search(pattern, "permit") or result
            else:
                result = re.search(pattern, "deny") or result

        return re.search(pattern, str(self.chain)) or result

    def to_string(self):
        """Return the string representation of the action"""
        if isinstance(self.chain, ACL):
            return self.chain.name

        if isinstance(self.chain, bool):
            return "permit" if self.chain else "deny"

        return str(self.chain)

    def get_action_color(self):
        """Return the color associated to the action (for gtk display)."""
        if isinstance(self.chain, bool):
            return "darkgreen" if self.chain else "darkred"
        return "darkblue"