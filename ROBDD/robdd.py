#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ite import Ite
from sys import maxint


class Robdd:
    # static helper methods

    @staticmethod
    def true():
        return Robdd.make(Ite(1, 1, 1))

    @staticmethod
    def false():
        return Robdd.make(Ite(1, 0, 0))

    @staticmethod
    def make_x(i):
        return Robdd.make(Ite(i, 1, 0))

    @staticmethod
    def make_not_x(i):
        return Robdd.make(Ite(i, 0, 1))

    @staticmethod
    def make(_ite):
        r = Robdd()
        r.build(_ite)
        return r

    # instance definition

    def __init__(self):
        self.clear()

    def clear(self):
        self.items = []
        self.items_append = self.items.append
        self.inverse = {}

        self.variables = []

        self.insert_attempts = 0
        self.insert_distinct = 0

        self.root = None  # root of the robdd tree

        self._insert(maxint, None, None)  # inserts a node for True
        self._insert(maxint, None, None)  # inserts a node for False


    # builds a structure from a Ite expression
    def build(self, expression):

        if not isinstance(expression, Ite):
            raise "Expression is not an Ite class object"

        self.root = self._build(expression)

        return self.root

    def _build(self, expression):

        inserting_t = expression.t if expression.t_is_bool() else self._build(expression.t)
        inserting_f = expression.f if expression.f_is_bool() else self._build(expression.f)

        return self.insert(expression.i, inserting_t, inserting_f)


    # inserts nodes w/ redundancy check
    # Num i - variable number
    # Num t - variable number of the T child
    # Num f - variable number of the F child
    def insert(self, i, t, f):

        # self.insert_variable(i)
        # self.insert_attempts += 1

        if t == f:
            # the t and the f children are equal, 
            # so the i variable can be ignored
            self.root = t
            return t

        # check if this is a redundant node
        # n = self.find_by_inverse(i, t, f)
        if (i, t, f) in self.inverse:
            n = self.inverse[(i, t, f)]
        else:
            n = len(self.items)

            self.items_append((i, t, f))
            self.inverse[(i, t, f)] = n
            # n = self._insert(i, t, f)
            # self.insert_distinct += 1

        self.root = n

        return n

    def compare(self, i, t, f):
        if t == f:
            return t
        if (i, t, f) in self.inverse:
            return self.inverse[(i, t, f)]
        else:
            n = len(self.items)
            self.inverse[(i, t, f)] = n
            return n

    def insert_variable(self, i):
        if i in self.variables:
            return

        self.variables.append(i)

    def _insert(self, v, t, f):
        index = len(self.items)

        self.items_append((v, t, f))
        self.inverse[(v, t, f)] = index

        return index

    def find_by_inverse(self, v, t, f):
        return self.inverse[(v, t, f)] if (v, t, f) in self.inverse else None


    def __str__(self):
        return self.show(self.root)

    def show(self, index, ident=0):
        ident_str = ident * " "

        if index <= 1:
            return ident_str + str(index)

        i, t, f = self.items[index]

        return ident_str + "x{}\n".format(i) + \
               self.show(t) + "\n" + \
               self.show(f)


    def list(self):
        result = ""

        for index in range(len(self.items)):
            i, t, f = self.items[index]
            result += "{} ({}, {}, {})\n".format(index, i, t, f)

        return result


    def get_root(self):
        return (len(self.items) - 1) if self.root == None else self.root


    def solutions_len(self):
        return self._solutions_len(self.get_root())

    def _solutions_len(self, index):
        if index < 0:
            raise "invalid index"

        if index < 2:
            return index

        i, t, f = self.items[index]

        return self._solutions_len(t) + self._solutions_len(f)

    def get_solutions(self):
        return self._get_solutions(self.get_root())

    def _get_solutions(self, index):
        result = []

        i, t, f = self.items[index]

        result.extend(self._get_solutions_in_child(i, t, True))
        result.extend(self._get_solutions_in_child(i, f, False))

        return result


    def _get_solutions_in_child(self, current_index, child_index, child_type):
        if child_index < 0:
            raise "Invalid index in T child"

        if child_index == 1:
            return [{current_index: child_type}]

        if child_index == 0:
            return []

        # now child index is greater than 1

        child_solutions = self._get_solutions(child_index)
        result = []

        for solution in child_solutions:
            solution[current_index] = child_type
            result.append(solution)

        return result
        

