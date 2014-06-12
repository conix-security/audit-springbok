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
        # create multiprocess jobs
        for acl in self.firewall.acl:
            jobs.append(multiprocessing.Process(target=_detect_anomaly, args=(acl.rules, result_queue, processed_id_rules, self.deep_search)))

        Gtk.Gtk_Main.Gtk_Main().create_progress_bar("Anomaly detection", self.firewall.get_nb_rules(), self._cancel_detection, *(jobs))

        # start jobs
        for job in jobs: job.start()
        # empty queue
        while reduce(lambda x, y: x | y, [job.is_alive() for job in jobs], False):
            result += [result_queue.get() for i in xrange(result_queue.qsize())]
            processed = reduce(lambda x, _: x + 1, [processed_id_rules.get() for _ in xrange(processed_id_rules.qsize())], 0)
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


def _detect_anomaly(rules, result_queue, processed_id_rules, deep_search):
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
    rules : Rule list. The list of rule to inspect
    result_queue : multiprocessing Queue. A queue to put errors
    """
    remain = Robdd.true()
    accept = Robdd.false()
    deny = Robdd.false()
    error_list = deque()
    error_list_append = error_list.append

    for rule in rules:
        processed_id_rules.put(rule.identifier)
        error_rules = deque()
        # Pj ⊆ Rj
        if compare_bdd(rule.toBDD(), Bdd.IMPL, remain):
            pass
        else:
            # Pj ∩ Rj = ∅
            if not compare_bdd(rule.toBDD(), Bdd.AND, remain):
                # Pj ⊆ Dj
                if compare_bdd(rule.toBDD(), Bdd.IMPL, (deny if rule.action else accept)):
                    if deep_search:
                        for r in rules:
                            if r == rule:
                                break
                            # ∀ x < j, ∃ <Px, deny> such that Px ∩ Pj != ∅
                            if r.action != rule.action and compare_bdd(r.toBDD(), Bdd.AND, rule.toBDD()):
                                error_rules.append(r)
                    error_list_append(AnomalyError.error_message(ErrorType.INT_MASK_SHADOW, ErrorType.ERROR, rule, error_rules))
                # Pj ∩ Dj = ∅
                elif not compare_bdd(rule.toBDD(), Bdd.AND, (deny if rule.action else accept)):
                    if deep_search:
                        for r in rules:
                            if r == rule:
                                break
                            # ∀ x < j, ∃ <Px, accept> such that Px ∩ Pj != ∅
                            if r.action == rule.action and compare_bdd(r.toBDD(), Bdd.AND, rule.toBDD()):
                                error_rules.append(r)
                    error_list_append(AnomalyError.error_message(ErrorType.INT_MASK_REDUNDANT, ErrorType.ERROR, rule, error_rules))
                else:
                    if deep_search:
                        for r in rules:
                            if r == rule:
                                break
                            # ∀ x < j, ∃ Px such that Px ∩ Pj != ∅
                            if compare_bdd(r.toBDD(), Bdd.AND, rule.toBDD()):
                                error_rules.append(r)
                    error_list_append(AnomalyError.error_message(ErrorType.INT_MASK_REDUNDANT_CORRELATION, ErrorType.ERROR, rule, error_rules))
            else:
                error_redudant = deque()
                error_generalization = deque()
                if deep_search:
                    # if deep search try to distinguish overlap of generalization or redundancy
                    for r in rules:
                        if r == rule:
                            break
                        # ∀ x < j, ∃ <Px, deny> such that Px ⊆ Pj
                        if r.action != rule.action and compare_bdd(r.toBDD(), Bdd.IMPL, rule.toBDD()):
                            error_generalization.append(r)
                        # ∀ x < j, ∃ <Px, accept> such that Px ⊆ Pj
                        elif r.action == rule.action and compare_bdd(r.toBDD(), Bdd.IMPL, rule.toBDD()):
                            error_redudant.append(r)
                        elif compare_bdd(r.toBDD(), Bdd.AND, rule.toBDD()):
                            error_rules.append(r)
                    if error_redudant:
                        error_list_append(AnomalyError.error_message(ErrorType.INT_PART_REDUNDANT, ErrorType.ERROR, rule, error_redudant))
                    if error_generalization:
                        error_list_append(AnomalyError.error_message(ErrorType.INT_PART_GENERALIZATION, ErrorType.WARNING, rule, error_generalization))
                    if error_rules:
                        error_list_append(AnomalyError.error_message(ErrorType.INT_PART_CORRELATION, ErrorType.WARNING, rule, error_rules))
                else:
                    error_list_append(AnomalyError.error_message(ErrorType.INT_PART_CORRELATION, ErrorType.WARNING, rule, error_rules))

        if rule.action:
            accept = synthesize(accept, Bdd.OR, synthesize(remain, Bdd.AND, rule.toBDD()))
        else:
            deny = synthesize(deny, Bdd.OR, synthesize(remain, Bdd.AND, rule.toBDD()))
        remain = synthesize(Robdd.true(), Bdd.AND, negate_bdd(synthesize(accept, Bdd.OR, deny)))

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
                error_list_append(AnomalyError.error_message(ErrorType.INT_PART_GENERALIZATION, ErrorType.WARNING, rx, ry))
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