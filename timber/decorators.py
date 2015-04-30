# -*- coding: utf-8 -*-

import sys, logging

logger = logging.getLogger('')
#logger.setLevel(logging.DEBUG)

class Wrapper(object):
    '''
    Wrap up classes from checkers.py (called any of them XChecker) :

    1. if exception happens in XChecker.__init__,
        __call__ returns Wrapper class instance
        instead of XChecker class instance ;
    2. overload __getattr__ to avoid AttributeError
        exceptions, when we have already intercepted
        the instance of XChecker.

    -- Wrapper class-decorator saves only from exceptions in XChecker.__init__() methods ;
    -- XChecker attribute-method calls are wrapped from exceptions in Patterns classes by
        standard exception handling mechanism ;
    -- todo : finish interface of BeautifulBody class : possibility to setup <failobj> argument
        in attribute-method calls, in case if a message don't have processing header at all or
        there is nothing interesting in its value .
    '''

    def __init__(self, checker_cls):

        self.checker = checker_cls

    def __call__(self, pattern_inst):

        try:

            self.checker_inst = self.checker(pattern_inst)
            #logger.debug(str(self.checker_inst.__class__)+' was successfully initialized.')

        except Exception as err:
            logger.warn('Can\'t initialize '+self.checker.__name__+' for processing msg :')
            logger.warn(str(err))
            self.checker_inst = self
            logger.debug(str(self)+' will intercept it.')

        return self.checker_inst













