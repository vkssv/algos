# -*- coding: utf-8 -*-

import sys, os, importlib


class PatternFactory(object):
    """ Factory for creating flying Frankensteins """

    def New(self, msg, label):
        #logger.debug(label)
        try:
            pattern = importlib.import_module(label + '_pattern')
            # logger.debug ((check.title()).replace('_',''))
            current_obj = getattr(pattern, (label.title() + 'Pattern'))

        except Exception as details:
            raise

        return (current_obj(msg))


MetaFrankenstein = PatternFactory()
