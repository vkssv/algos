# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math
from pattern_wrapper import BasePattern

INIT_SCORE = BasePattern.INIT_SCORE

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)


class Wrapper(object):
    '''
    Wrap up classes from checkers.py :

    1. if exception happens on Checker-initialisation stage,
    __call__ returns self instead of wrapped Checker's class ;
    2. overload __getattr__ to avoid AttributeError exceptions,
    when Checker's attribute methods would be called from Pattern-classes.

    '''

    def __init__(self, checker_cls):

        self.checker = checker_cls

    def __call__(self, *args):

        try:
            self.checker_inst = self.checker(*args)
            logger.debug(str(self.checker_inst.__class__)+' was successfully initialized.')

        except Exception as err:
            logger.warn('Can\'t initialize '+self.checker.__name__+' for processing msg :')
            logger.warn('error : '.upper()+str(err))
            self.checker_inst = self
            logger.debug(str(self.__name__)+' will intercept it.')

        return self.checker_inst

    def __getattr__(self, attr_name):
        return lambda : INIT_SCORE












