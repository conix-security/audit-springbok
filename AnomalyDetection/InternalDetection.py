#! /usr/bin/env python
# -*- coding: utf-8 -*-

from ROBDD.robdd import Robdd
from ROBDD.synthesis import synthesize, compare, negate_bdd
from ROBDD.operators import Bdd
from AnomalyError import AnomalyError
from AnomalyError import ErrorType
from collections import deque
import multiprocessing
import time
import gtk
import Gtk.Gtk_Main


class InternalDetection:
    """InternalDetection class.
    Implement the internal detection algorithm.

    Parameters
    ----------
    node : Node. The node to test
    deep_search : bool. Enable deep search.
    firewall : Firewall. The firewall to test
    result : list. A list of string of detected error
    """
    def __init__(self, node, deep_search):
        self.node = node
        self.deep_search = deep_search
        self.firewall = node.object
        self.result = []

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['node']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.node = None

    def _cancel_detection(self, widget, jobs):
        """Cancel button. Kill all jobs"""
        [job.terminate() for job in jobs[0]]

    def detect_anomaly(self):
        """Detect internal anomaly.

        Return
        ------
        Return the list of detected errors
        """
        t0 = time.time()
        result = []
        jobs = []
        result_queue = multiprocessing.Queue()
        processed_id_rules = multiprocessing.Queue()
        acl_list = get_rule_path(self.firewall)
        # create multiprocess jobs
        for acl in self.firewall.acl:
            jobs.append(multiprocessing.Process(target=_detect_anomaly, args=(acl, [], [], [],
                                                                              Robdd.true(), Robdd.false(), Robdd.false(),
                                                                              result_queue, processed_id_rules, self.deep_search)))

        Gtk.Gtk_Main.Gtk_Main().create_progress_bar("Anomaly detection", sum([len(a) for a in acl_list]),
                                                    self._cancel_detection, *(jobs))

        # start jobs
        for job in jobs: job.start()
        # empty queue
        while reduce(lambda x, y: x | y, [job.is_alive() for job in jobs], False):
            result += [result_queue.get() for _ in xrange(result_queue.qsize())]
            processed = reduce(lambda x, _: x + 1,
                               [processed_id_rules.get() for _ in xrange(processed_id_rules.qsize())], 0)
            Gtk.Gtk_Main.Gtk_Main().update_progress_bar(processed)
            Gtk.Gtk_Main.Gtk_Main().update_interface()
            time.sleep(0.1)
        # wait jobs finish
        for job in jobs: job.join()

        result += [result_queue.get() for i in xrange(result_queue.qsize())]
        self.result = result

        t1 = time.time()

        Gtk.Gtk_Main.Gtk_Main().change_statusbar('Anomaly internal detection process in %.3f secondes' % (t1 - t0))
        Gtk.Gtk_Main.Gtk_Main().destroy_progress_bar()

        return result


def get_rule_path(firewall):
    """Get the list of rule for each path."""
    result = []
    for acl in firewall.acl:
        result += acl.get_rules_path()
    return result


def _detect_anomaly(acl, stack, parsed_rule, visited, remain, accept, deny, result_queue, processed_id_rules, deep_search):
    """Recursive algorithm for ACL graph traversal.
    This recursive algorithm construct the list of all possible list of rule for the ACL chained model.
    Then it launch the _classify_anomaly function on each rule and try to detect anomaly if any.

    Parameters
    ----------
    acl : ACL. The acl to inspect.
    stack : list of Rule list. A stack of rule list.
    parsed_rule : Rule list. A list of parse rule.
    visisted : ACL list. List of visited ACL.
    remain : ROBDD. Remain ROBDD.
    accept : ROBDD. Accept ROBDD.
    deny : ROBDD. Deny ROBDD.
    result_queue : list. List of error.
    processed_id_rules : list. List of processed rules.
    deep_search : Bool. If true find blamed rules.
    """
    if acl not in visited:
        visited.append(acl)
        stack.append(list(acl.rules))

    while stack:
        rule_list = stack[-1]
        while rule_list:
            rule = rule_list.pop(0)
            processed_id_rules.put(rule.identifier)
            _classify_anomaly(rule, parsed_rule, remain, accept, deny, result_queue, deep_search)
            parsed_rule.append([rule, rule.action.chain, rule.toBDD()])
            if rule.action.is_chained() or rule.action.is_return():
                # a = accept & True -> copy of accept
                a = synthesize(accept, Bdd.AND, Robdd.true())
                # d = D ∪ (R ∩ ¬P)
                d = synthesize(deny, Bdd.OR, synthesize(remain, Bdd.AND, negate_bdd(rule.toBDD())))
                # r = I ∩ ¬(a ∪ d)
                r = synthesize(Robdd.true(), Bdd.AND, negate_bdd(synthesize(a, Bdd.OR, d)))
                # copy stack of rules
                stack_copy = [list(i) for i in stack]
                visited_copy = list(visited)
                parsed_rule_copy = list(parsed_rule)
                parsed_rule_copy[-1] = [parsed_rule_copy[-1][0], False, negate_bdd(parsed_rule_copy[-1][0].toBDD())]

                if rule.action.is_chained():
                    _detect_anomaly(rule.action.chain, stack_copy, parsed_rule_copy, visited_copy, r, a, d,
                                    result_queue, processed_id_rules, deep_search)
                else:
                    # remove current stack rule
                    stack_copy.pop()
                    visited_copy.pop()
                    # special case RETURN in first ACL
                    if not visited_copy:
                        stack_copy = [[acl.rules[-1]]]
                        visited_copy.append(acl)
                    _detect_anomaly(visited_copy[-1], stack_copy, parsed_rule_copy, visited_copy, r, a, d,
                                    result_queue, processed_id_rules, deep_search)
            else:  # rule is Permit or Deny
                if rule.action.chain:
                    # accept = A ∪ (R ∩ P)
                    accept = synthesize(accept, Bdd.OR, synthesize(remain, Bdd.AND, rule.toBDD()))
                else:
                    # d = D ∪ (R ∩ P)
                    deny = synthesize(deny, Bdd.OR, synthesize(remain, Bdd.AND, rule.toBDD()))
            # remain = I ∩ ¬(a ∪ d)
            remain = synthesize(Robdd.true(), Bdd.AND, negate_bdd(synthesize(accept, Bdd.OR, deny)))
        stack.pop()
        visited.pop()


def _classify_anomaly(rule, rules, remain, accept, deny, result_queue, deep_search):
    """Detect anomaly of the given rule set.
    This algorithm is derived from the algorithm of Fireman.
    It uses ROBDD to compare each rules.
    The complexity of this algorithm is in O(n).

    For more informations read :
    - Firewall Policy Advisor for Anomaly Detection and rules analysis,
    http://www.arc.uncc.edu/pubs/im03-cr.pdf
    - FIREMAN : A Toolkit for FIREwall Modeling and ANalysis,
    http://www.cs.ucdavis.edu/~su/publications/fireman.pdf

    Parameters
    ----------
    rule : Rule. The rule to inspect
    rules : Rule list. List of preceding rule.
    result_queue : multiprocessing Queue. A queue to put errors
    """
    error_list = deque()
    error_list_append = error_list.append
    error_rules = deque()

    # Pj ⊆ Rj
    if compare_bdd(rule.toBDD(), Bdd.IMPL, remain):
        return
    else:
        # Pj ∩ Rj = ∅
        if not compare_bdd(rule.toBDD(), Bdd.AND, remain):
            # Pj ⊆ Dj
            if compare_bdd(rule.toBDD(), Bdd.IMPL, (deny if rule.action.chain else accept)):
                if deep_search:
                    for r, a, b in rules:
                        # ∀ x < j, ∃ <Px, deny> such that Px ∩ Pj != ∅
                        if a != rule.action.chain and compare_bdd(b, Bdd.AND, rule.toBDD()):
                            error_rules.append(r)
                error_list_append(
                    AnomalyError.error_message(ErrorType.INT_MASK_SHADOW, ErrorType.ERROR, rule, error_rules))
            # Pj ∩ Dj = ∅
            elif not compare_bdd(rule.toBDD(), Bdd.AND, (deny if rule.action.chain else accept)):
                if deep_search:
                    for r, a, b in rules:
                        # ∀ x < j, ∃ <Px, accept> such that Px ∩ Pj != ∅
                        if a == rule.action.chain and compare_bdd(b, Bdd.AND, rule.toBDD()):
                            error_rules.append(r)
                error_list_append(
                    AnomalyError.error_message(ErrorType.INT_MASK_REDUNDANT, ErrorType.ERROR, rule, error_rules))
            else:
                if deep_search:
                    for r, a, b in rules:
                        # ∀ x < j, ∃ Px such that Px ∩ Pj != ∅
                        if compare_bdd(b, Bdd.AND, rule.toBDD()):
                            error_rules.append(r)
                error_list_append(
                    AnomalyError.error_message(ErrorType.INT_MASK_REDUNDANT_CORRELATION, ErrorType.ERROR, rule,
                                               error_rules))
        else:
            error_redundant = deque()
            error_generalization = deque()
            if deep_search:
                # if deep search try to distinguish overlap of generalization or redundancy
                for r, a, b in rules:
                    # ∀ x < j, ∃ <Px, deny> such that Px ⊆ Pj
                    if a != rule.action.chain and compare_bdd(b, Bdd.IMPL, rule.toBDD()):
                        error_generalization.append(r)
                    # ∀ x < j, ∃ <Px, accept> such that Px ⊆ Pj
                    elif a == rule.action.chain and compare_bdd(b, Bdd.IMPL, rule.toBDD()):
                        error_redundant.append(r)
                    elif compare_bdd(b, Bdd.AND, rule.toBDD()):
                        error_rules.append(r)
                if error_redundant:
                    error_list_append(
                        AnomalyError.error_message(ErrorType.INT_PART_REDUNDANT, ErrorType.ERROR, rule, error_redundant))
                if error_generalization:
                    error_list_append(
                        AnomalyError.error_message(ErrorType.INT_PART_GENERALIZATION, ErrorType.WARNING, rule,
                                                   error_generalization))
                if error_rules:
                    error_list_append(
                        AnomalyError.error_message(ErrorType.INT_PART_CORRELATION, ErrorType.WARNING, rule,
                                                   error_rules))
            else:
                error_list_append(
                    AnomalyError.error_message(ErrorType.INT_PART_CORRELATION, ErrorType.WARNING, rule, error_rules))

    result_queue.put(error_list)


def _detect_anomaly_n2(rules, result_queue):
    """Detect anomaly of the given rule set.
    This algorithm is a light version who compare rules 2 by 2.
    It uses ROBDD to compare relation between each rules.
    The complexity of this algorithm is in O(n^2).

    For more informations read :
    - Firewall Policy Advisor for Anomaly Detection and rules analysis,
    http://www.arc.uncc.edu/pubs/im03-cr.pdf
    - FIREMAN : A Toolkit for FIREwall Modeling and ANalysis,
    http://www.cs.ucdavis.edu/~su/publications/fireman.pdf

    Parameters
    ----------
    rules : Rule list. The list of rule to inspect
    result_queue : multiprocessing Queue. A queue to put errors
    """
    error_list = deque()
    error_list_append = error_list.append

    for x in xrange(len(rules)):
        rx = rules[x]
        y = x + 1
        while y < len(rules):
            ry = rules[y]
            # Rx ∩ Ry = ∅
            if not compare_bdd(rx.toBDD(), Bdd.AND, ry.toBDD()):
                pass
            # Ry ⊆ Rx
            elif compare_bdd(rx.toBDD(), Bdd.IMPL, ry.toBDD()):
                error_list_append(AnomalyError.error_message(ErrorType.INT_MASK_SHADOW, ErrorType.ERROR, ry, rx))
            # Rx ⊆ Ry
            elif compare_bdd(ry.toBDD(), Bdd.IMPL, rx.toBDD()):
                error_list_append(
                    AnomalyError.error_message(ErrorType.INT_PART_GENERALIZATION, ErrorType.WARNING, rx, ry))
            # Rx ∩ Ry != ∅
            else:
                error_list_append(AnomalyError.error_message(ErrorType.INT_PART_CORRELATION, ErrorType.ERROR, rx, ry))
            y += 1

    result_queue.put(error_list)


def compare_bdd(bdd1, operator, bdd2):
    """Compare two ROBDD"""
    res = compare(bdd1, operator, bdd2)

    if operator == Bdd.IMPL:
        return res <= 2
    elif operator == Bdd.AND:
        return not res <= 2