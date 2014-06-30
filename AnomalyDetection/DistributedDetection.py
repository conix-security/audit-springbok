#! /usr/bin/env python
# -*- coding: utf-8 -*-

from ROBDD.robdd import Robdd
from ROBDD.synthesis import synthesize, compare, negate_bdd
from ROBDD.operators import Bdd
from AnomalyError import AnomalyError
from AnomalyError import ErrorType
from collections import deque
import time
from NetworkGraph import NetworkGraph
import networkx as nx
from SpringBase.Firewall import Firewall
import Gtk.Gtk_Main
from SpringBase.Rule import Rule
from SpringBase.Action import Action


class DistributedDetection:
    """DistributedDetection class.
    Implementation of the distributed detection algorithm.

    Parameters
    ----------
    deep_search : bool. Enable deep search.
    error_path : List. List of error with corresponding path
    cancel : bool. Used to cancel detection. If True cancel detection and return
    """
    def __init__(self, deep_search):
        self.deep_search = deep_search
        self.error_path = []
        self.cancel = False

    def __getstate__(self):
        """Used by Pickle for saving"""
        state = self.__dict__.copy()
        return state

    def __setstate__(self, state):
        """Used by Pickle for loading"""
        self.__dict__.update(state)

    def _cancel_detection(self, widget, *args):
        """Callback function for canceling detection"""
        self.cancel = True

    def distributed_detection(self):
        """Distributed detection algorithm.
        Find all simple path between each node.
        For each path try to detect distributed anomaly

        Return
        ------
        Return the list of error found
        """
        t0 = time.time()
        error_list = deque()
        g = NetworkGraph.NetworkGraph().multidigraph
        # reverse graph to compute rooted tree path
        g_reverse = NetworkGraph.NetworkGraph().get_reversed_multidigraph()
        Gtk.Gtk_Main.Gtk_Main().create_progress_bar("Anomaly detection", count_nb_rules(g, g_reverse), self._cancel_detection)

        # Detect path between each couple of node
        for source in g.nodes():
            if self.cancel:
                break
            if isinstance(source, Firewall) or source is None:
                continue
            for target in g.nodes():
                if self.cancel:
                    break
                if isinstance(target, Firewall) or target is source or target is None:
                    continue
                path_res = get_rooted_tree(g_reverse, source, target, set())
                if path_res:
                    remain, tmp_error = self._tree_parse_detection(path_res)
                    error_list.append([source.to_string() + " -> " + target.to_string(), tmp_error])

        self.error_path = error_list

        t1 = time.time()
        Gtk.Gtk_Main.Gtk_Main().change_statusbar('Anomaly distributed detection process in %.3f secondes' % (t1 - t0))
        Gtk.Gtk_Main.Gtk_Main().destroy_progress_bar()

        return error_list

    def _tree_parse_detection(self, tree_path):
        """Detect anomalies given a rooted tree

        Parameters
        ----------
        tree_path : nested list. Rooted tree representation

        Return
        ------
        Return a tuple containing the accepted packets and a list of detected errors
        """
        error_list = []
        parent = tree_path[0]
        remain = Robdd.false()
        for i in xrange(1, len(tree_path)):
            acl_list = NetworkGraph.NetworkGraph().get_acl_list(src=tree_path[i][0], dst=parent)
            # test is leaf
            if len(tree_path[i]) == 1:
                res_remain, res_error = self._distributed_detection(acl_list, Robdd.true(), tree_path[i])
                res_error = []
            else:
                res_remain, res_error = self._tree_parse_detection(tree_path[i])
                error_list += res_error
                res_remain, res_error = self._distributed_detection(acl_list, res_remain, tree_path[i])
            error_list += res_error
            remain = synthesize(remain, Bdd.OR, res_remain)

        return remain, error_list

    def _distributed_detection(self, acl_list, remain, tree_path):
        """Detection method for a given acl with a given remain ROBDD.
        This algorithm is derived from the algorithm of Fireman.

        For more informations read :
        - Firewall Policy Advisor for Anomaly Detection and rules analysis,
        http://www.arc.uncc.edu/pubs/im03-cr.pdf
        - FIREMAN : A Toolkit for FIREwall Modeling and ANalysis,
        http://www.cs.ucdavis.edu/~su/publications/fireman.pdf

        Parameters
        ----------
        acl : Rule list. The rule list to test
        remain : ROBDD. The remaining ROBDD

        Return
        ------
        Return a tuple of remaining rules and the list error found in this context
        """
        accept_robdd_list = []
        error_list = deque()
        error_list_append = error_list.append

        for acl in acl_list:
            for rule_path in acl.get_rules_path():
                accept = Robdd.false()
                deny = Robdd.false()
                if self.cancel:
                    break
                for rule, action in rule_path:
                    if self.cancel:
                        break
                    Gtk.Gtk_Main.Gtk_Main().update_progress_bar(1)
                    Gtk.Gtk_Main.Gtk_Main().update_interface()
                    error_rules = []
                    rule_action = rule.action.chain if isinstance(rule.action.chain, bool) else action
                    if rule_action:
                        # P ⊆ I
                        if compare_bdd(rule.toBDD(), Bdd.IMPL, remain):
                            pass
                        # P ⊆ ¬I
                        elif compare_bdd(rule.toBDD(), Bdd.IMPL, negate_bdd(remain)):
                            if self.deep_search:
                                # ∀ ACLx < ACLj, ∀ x ∈ ACLx, ∃ <Px, deny> such that Px ∩ Pj != ∅
                                error_rules = self.search_rules(rule, Bdd.AND, False, tree_path)
                            error_list_append(
                                AnomalyError.error_message(ErrorType.DIST_SHADOW, ErrorType.ERROR, rule, error_rules))
                        # P ∩ I != ∅
                        else:
                            if self.deep_search:
                                # ∀ ACLx < ACLj, ∀ x ∈ ACLx, ∃ <Px, deny> such that Px ∩ Pj
                                error_rules = self.search_rules(rule, Bdd.AND, False, tree_path)
                            error_list_append(
                                AnomalyError.error_message(ErrorType.DIST_CORRELATE, ErrorType.WARNING, rule, error_rules))
                    else:
                        # P ⊆ I
                        if compare_bdd(rule.toBDD(), Bdd.IMPL, remain):
                            if self.deep_search:
                                # ∀ ACLx < ACLj, ∀ x ∈ ACLx, ∃ <Px, accept> such that Px ∩ Pj
                                error_rules = self.search_rules(rule, Bdd.AND, True, tree_path)
                            error_list_append(
                                AnomalyError.error_message(ErrorType.DIST_RAISED, ErrorType.WARNING, rule, error_rules))
                        # P ⊆ ¬I
                        elif compare_bdd(rule.toBDD(), Bdd.IMPL, negate_bdd(remain)):
                            if self.deep_search:
                                # ∀ ACLx < ACLj, ∀ x ∈ ACLx, ∃ <Px, deny> such that Px ∩ Pj
                                error_rules = self.search_rules(rule, Bdd.AND, False, tree_path)
                            error_list_append(
                                AnomalyError.error_message(ErrorType.DIST_REDUNDANT, ErrorType.WARNING, rule, error_rules))
                        # P ∩ I != ∅
                        else:
                            if self.deep_search:
                                # ∀ ACLx < ACLj, ∀ x ∈ ACLx such that Px ∩ Pj
                                error_rules = self.search_rules(rule, Bdd.AND, None, tree_path)
                            error_list_append(
                                AnomalyError.error_message(ErrorType.DIST_CORRELATE, ErrorType.WARNING, rule, error_rules))

                    # update value
                    if rule.action.is_chained() or rule.action.is_return():
                        if action:
                            # D = D ∪ ¬(A ∪ P) = D ∪ (¬A ∩ ¬P)
                            deny = synthesize(deny, Bdd.OR, negate_bdd(synthesize(accept, Bdd.OR, rule.toBDD())))
                        else:
                            # D = D ∪ (¬A ∩ P)
                            deny = synthesize(deny, Bdd.OR, synthesize(negate_bdd(accept), Bdd.AND, rule.toBDD()))
                    else:
                        if rule.action.chain:
                            # A = A ∪ (¬D ∩ P)
                            accept = synthesize(accept, Bdd.OR, synthesize(negate_bdd(deny), Bdd.AND, rule.toBDD()))
                        else:
                            # D = D ∪ (¬A ∩ P)
                            deny = synthesize(deny, Bdd.OR, synthesize(negate_bdd(accept), Bdd.AND, rule.toBDD()))
                accept_robdd_list.append(accept)

        res_accept = Robdd.false()
        for a in accept_robdd_list:
            res_accept = synthesize(res_accept, Bdd.OR, a)

        return res_accept, error_list

    def search_rules(self, rule, operator, action, tree_path):
        """Deep search option.
        Reparse all rules corresponding to the anomaly.

        Parameters
        ----------
        rule : Rule. The rule to compare
        operator : Bdd.Operator. The operation to perform
        action : Bool or None. Filter rules having this action
        path : the current tested path
        index_path : the current position of the rule in the current path"""
        error_rules = deque()
        parent = tree_path[0]
        for i in xrange(1, len(tree_path)):
            if self.cancel:
                break
            if isinstance(i, list):
                error_rules.append(self.search_rules(rule, operator, action, tree_path[i]))
            acl_list = NetworkGraph.NetworkGraph().get_acl_list(src=parent, dst=tree_path[i][0])
            for acl in acl_list:
                for rule_path in acl.get_rules_path():
                    for r, a in rule_path:
                        rule_action = r.action.chain if isinstance(r.action.chain, bool) else a
                        if action and a != action:
                            continue
                        if compare_bdd(rule.toBDD(), operator, r.toBDD()):
                            error_rules.append(r)

        if not error_rules:
            error_rules.append(Rule(-1, 'probably implicit deny', [], [], [], [], [], Action(False)))

        return error_rules


def get_rooted_tree(graph, source, target, visited):
    """Create a nested list of a rooted tree with source as leaf and target as root.

    Parameters
    ----------
    graph : MultiDiGraph. networkX multidigraph reversed for path search
    source : Ip. souce node
    target : Ip. target node
    visited : set. Set of visited path"""
    if source == target:
        return [source]
    res = []
    visited.add(target)
    for n in nx.neighbors(graph, target):
        if n not in visited:
            tmp = get_rooted_tree(graph, source, n, set(visited))
            if tmp:
                res.append(tmp)
    if res:
        res.insert(0, target)

    return res


def compare_bdd(bdd1, operator, bdd2):
    """Compare two ROBDD"""
    res = compare(bdd1, operator, bdd2)

    if operator == Bdd.IMPL:
        return res <= 2
    elif operator == Bdd.AND:
        return not res <= 2


def bdd_to_string(bdd):
    """Convert a ROBDD to string (used for memoization)"""
    return str(bdd.root) + ' ' + bdd.list()


def count_nb_rules(g, g_reverse):
    """Count the number of rules in all path. Used for the progress bar

    Parameters
    ----------
    g : MultiDiGraph. The topology graph
    g_reverse : MultiDiGraph. The reversed graph of g

    Return
    ------
    Return the number of rules counted"""
    def count_rules(tree_path):
        res = 0
        for i in xrange(1, len(tree_path)):
            # test is leaf
            if not len(tree_path[i]) == 1:
                res += count_rules(tree_path[i])
            acl_list = NetworkGraph.NetworkGraph().get_acl_list(src=tree_path[i][0], dst=tree_path[0])
            res += reduce(lambda x, y: x + y, [len(acl.rules) for acl in acl_list], 0)
        return res

    nb_rules = 0

    for source in g.nodes():
        if isinstance(source, Firewall):
            continue
        for target in g.nodes():
            if isinstance(target, Firewall) or target is source:
                continue
            path_res = get_rooted_tree(g_reverse, source, target, set())
            nb_rules += count_rules(path_res)

    return nb_rules