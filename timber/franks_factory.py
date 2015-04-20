# -*- coding: utf-8 -*-

import sys, os, importlib


class PatternFactory(object):
    """ Factory for creating flying Frankensteins """

    def New(self, label):
        #logger.debug(label)
        try:
            pattern = importlib.import_module(label + '_pattern')
            # logger.debug ((check.title()).replace('_',''))
            current_obj = getattr(pattern, (label.title() + 'Pattern'))

        except Exception as details:
            raise

        return current_obj


MetaFrankenstein = PatternFactory()

'''
@classmethod
def from_string(cls, date_as_string):
    day, month, year = map(int, date_as_string.split('-'))
    date1 = cls(day, month, year)
    return date1
'''
