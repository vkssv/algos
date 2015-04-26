# -*- coding: utf-8 -*-

import sys, os, importlib

class PatternFactory(object):
    """
    Factory for generating Patterns classes,
    according to processed label (spam, ham, nets, infos)
    """

    def New(self, label):

        try:
            pattern = importlib.import_module(label + '_pattern')
            current_obj = getattr(pattern, (label.title() + 'Pattern'))

        except Exception as details:
            raise

        return current_obj

MetaPattern = PatternFactory()


