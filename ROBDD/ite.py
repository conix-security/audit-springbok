#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Ite:

    # initializes a Ite (if-then-else) Graph Node
    # Num i - variable number
    # Bool | Ite t - true child
    # Bool | Ite f - false child
    def __init__(self, i, t, f):
        self.i = i
        self.t = t
        self.f = f

    # tells if the T child is a leaf
    def t_is_bool(self):
        return isinstance(self.t, int) and (self.t == 0 or self.t == 1)

    # tells if the F child is a leaf
    def f_is_bool(self):
        return isinstance(self.f, int) and (self.f == 0 or self.f == 1)

    def __str__(self):
        return "Ite(x{}, {}, {})".format(self.i, str(self.t), str(self.f))

    def pretty(self, ident=0):
        ident_str = " " * ident
        pretty_t = (ident_str + str(self.t)) if self.t_is_bool() else self.t.pretty(ident + 4)
        pretty_f = (ident_str + str(self.f)) if self.f_is_bool() else self.f.pretty(ident + 4)

        return ident_str + "if x{}".format(self.i) + "\n" \
            + pretty_t + "\n" \
            + pretty_f + "\n"

