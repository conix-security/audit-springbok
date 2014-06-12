#!/usr/bin/env python
# -*- coding: utf-8 -*-

from robdd import Robdd
from operators import Bdd
from collections import defaultdict, deque


# a shorthand function to abstract Synthesis class usage
def synthesize(expression_a, operator, expression_b):
    s = Synthesis()

    s.expression_a = expression_a
    s.expression_b = expression_b
    s.operator = operator

    return s.synthesize()


# used for comparison only, faster because it don't build the bdd
def compare(expression_a, operator, expression_b):
    s = Synthesis()

    s.expression_a = expression_a
    s.expression_b = expression_b
    s.operator = operator

    return s.compare()


# negate a bdd (just invert the value of node pointing to leafs)
def negate_bdd(bdd):
    neg_bdd = synthesize(bdd, Bdd.AND, Robdd.true())
    for i in xrange(len(neg_bdd.items)):
        neg_bdd.items[i] = tuple((neg_bdd.items[i][0],
                                  not neg_bdd.items[i][1] if neg_bdd.items[i][1] in (True, False) else neg_bdd.items[i][
                                      1],
                                  not neg_bdd.items[i][2] if neg_bdd.items[i][2] in (True, False) else neg_bdd.items[i][
                                      2]))

    # invert root, if root is a leaf
    if neg_bdd.root in (0, 1):
        neg_bdd.root ^= 1

    return neg_bdd


# makes an operation over two expressions with an operator
class Synthesis:
    def __init__(self):
        self.memo = defaultdict()

        self.operator = None
        self.expression_a = None
        self.expression_b = None

        self.result = None
        self.result_insert = None


    def synthesize(self):
        if self.expression_a == None or not isinstance(self.expression_a, Robdd):
            raise "Expression A is not a Robdd object."

        if self.expression_b == None or not isinstance(self.expression_b, Robdd):
            raise "Expression B is not a Robdd object."

        if self.operator not in [Bdd.AND, Bdd.OR, Bdd.IMPL, Bdd.BIIMPL]:
            raise "Invalid operator."

        self.result = Robdd()
        self.result_insert = self.result.insert
        self.result.root = self._synth(self.expression_a.root, self.expression_b.root)

        return self.result

    def compare(self):
        if self.expression_a == None or not isinstance(self.expression_a, Robdd):
            raise "Expression A is not a Robdd object."

        if self.expression_b == None or not isinstance(self.expression_b, Robdd):
            raise "Expression B is not a Robdd object."

        if self.operator not in [Bdd.AND, Bdd.OR, Bdd.IMPL, Bdd.BIIMPL]:
            raise "Invalid operator."

        self.result = Robdd()
        self.result_insert = self.result.compare
        self.result.root = self._synth(self.expression_a.root, self.expression_b.root)

        return len(self.result.inverse)

    def _synth(self, a_index, b_index):

        if (a_index, b_index) in self.memo:
            return self.memo[(a_index, b_index)]

        # print "_synth {}, {}".format(a_index, b_index)
        # print "   A is leaf:", self._is_leaf(a_index)
        # print "   B is leaf:", self._is_leaf(b_index)

        i_a, t_a, f_a = self.expression_a.items[a_index]
        i_b, t_b, f_b = self.expression_b.items[b_index]

        # if self._is_leaf(a_index) and self._is_leaf(b_index) :
        if a_index in (0, 1) and b_index in (0, 1):
            # print "   operating leaves"
            result = self._operate(a_index, b_index)

        elif i_a == i_b:
            # print "   operating nodes"
            result = self.result_insert(i_a,
                                        self._synth(t_a, t_b),
                                        self._synth(f_a, f_b))

        elif i_a < i_b:
            # print "   advancing A"
            result = self.result_insert(i_a,
                                        self._synth(t_a, b_index),
                                        self._synth(f_a, b_index))

        # elif i_a > i_b:
        else:
            # print "   advancing B"
            result = self.result_insert(i_b,
                                        self._synth(a_index, t_b),
                                        self._synth(a_index, f_b))

        self.memo[(a_index, b_index)] = result

        return result

    # iterative version. slower ...
    def _synth_iterative(self, a_index, b_index):
        stack_node = deque()
        stack_node_append = stack_node.append
        stack_node_pop = stack_node.pop
        insert_node = deque()
        insert_node_pop = insert_node.pop
        insert_node_append = insert_node.append
        res_node = defaultdict()
        memo = defaultdict()
        result = None
        parent_index = deque()
        parent_index_append = parent_index.append

        if a_index in (0, 1) and b_index in (0, 1):
            return self._operate(a_index, b_index)

        stack_node_append((a_index, b_index))

        while stack_node:
            a_index, b_index = stack_node_pop()
            if (a_index, b_index) in memo:
                result = memo[(a_index, b_index)]
                if insert_node[-1] not in res_node:
                    res_node[insert_node[-1]] = result
                else:
                    while True:
                        result = self.result_insert(insert_node[-1],
                                                    res_node.pop(insert_node[-1]),
                                                    result)
                        parent_index.pop()
                        insert_node.pop()
                        if not insert_node:
                            break

                        if insert_node[-1] not in res_node:
                            res_node[insert_node[-1]] = result
                            break
            elif a_index in (0, 1) and b_index in (0, 1):
                result = self._operate(a_index, b_index)
                memo[(a_index, b_index)] = result
                if insert_node[-1] not in res_node:
                    res_node[insert_node[-1]] = result
                else:
                    while True:
                        result = self.result_insert(insert_node[-1],
                                                    res_node.pop(insert_node[-1]),
                                                    result)
                        memo[parent_index.pop()] = result
                        insert_node_pop()
                        if not insert_node:
                            break

                        if insert_node[-1] not in res_node:
                            res_node[insert_node[-1]] = result
                            break
            else:
                i_a, t_a, f_a = self.expression_a.items[a_index]
                i_b, t_b, f_b = self.expression_b.items[b_index]
                parent_index_append((a_index, b_index))
                if i_a == i_b:
                    insert_node_append(i_a)
                    stack_node_append((f_a, f_b))
                    stack_node_append((t_a, t_b))
                elif i_a < i_b:
                    insert_node_append(i_a)
                    stack_node_append((f_a, b_index))
                    stack_node_append((t_a, b_index))
                else:
                    insert_node_append(i_b)
                    stack_node_append((a_index, f_b))
                    stack_node_append((a_index, t_b))

        return result

    def _operate(self, a_index, b_index):
        a = self._index_to_bool(a_index)
        b = self._index_to_bool(b_index)

        if self.operator == Bdd.AND:
            return a and b

        if self.operator == Bdd.OR:
            return a or b

        if self.operator == Bdd.IMPL:
            return not (a and not b)

        if self.operator == Bdd.BIIMPL:
            return a == b

        raise "Unknown operator."

    def _is_leaf(self, index):
        return index == 0 or index == 1

    def _index_to_bool(self, index):
        return index == 1
